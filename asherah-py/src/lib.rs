#![allow(non_local_definitions)]
#![allow(unsafe_code)]

use asherah as ael;
use asherah_config as config;
use once_cell::sync::Lazy;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::PyRef;

use std::collections::HashMap;
use std::sync::Mutex;

type Factory = ael::session::PublicFactory<
    ael::aead::AES256GCM,
    ael::builders::DynKms,
    ael::builders::DynMetastore,
>;
type SessionHandle = ael::session::PublicSession<
    ael::aead::AES256GCM,
    ael::builders::DynKms,
    ael::builders::DynMetastore,
>;

fn anyhow_to_py(err: anyhow::Error) -> PyErr {
    PyRuntimeError::new_err(err.to_string())
}

fn json_parse_err(err: impl std::fmt::Display) -> PyErr {
    PyRuntimeError::new_err(format!("invalid DataRowRecord JSON: {err}"))
}

#[pyfunction]
fn setup(config_obj: &PyAny) -> PyResult<()> {
    let py = config_obj.py();
    let json_module = py.import("json")?;
    let json_config: String = json_module
        .call_method1("dumps", (config_obj,))?
        .extract()?;
    let cfg = config::ConfigOptions::from_json(&json_config).map_err(anyhow_to_py)?;
    let (factory, applied) = config::factory_from_config(&cfg).map_err(anyhow_to_py)?;
    let mut guard = MANAGER.lock().expect("factory mutex poisoned");
    if guard.is_some() {
        return Err(PyRuntimeError::new_err(
            "Asherah already configured; call shutdown() first",
        ));
    }
    *guard = Some(FactoryManager::new(factory, applied));
    Ok(())
}

#[pyfunction]
fn shutdown() -> PyResult<()> {
    let mut guard = MANAGER.lock().expect("factory mutex poisoned");
    if let Some(manager) = guard.take() {
        manager.shutdown().map_err(anyhow_to_py)?;
    }
    Ok(())
}

#[pyfunction]
fn get_setup_status() -> PyResult<bool> {
    let guard = MANAGER.lock().expect("factory mutex poisoned");
    Ok(guard.is_some())
}

#[pyfunction]
fn setenv(env_obj: &PyAny) -> PyResult<()> {
    let py = env_obj.py();
    let value = if let Ok(s) = env_obj.extract::<&str>() {
        serde_json::from_str::<serde_json::Value>(s)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?
    } else {
        let json_module = py.import("json")?;
        let dumped: String = json_module.call_method1("dumps", (env_obj,))?.extract()?;
        serde_json::from_str::<serde_json::Value>(&dumped)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?
    };

    let obj = value
        .as_object()
        .ok_or_else(|| PyRuntimeError::new_err("environment payload must be a JSON object"))?;
    let os_module = py.import("os")?;
    let environ = os_module.getattr("environ")?;
    for (key, val) in obj {
        match val {
            serde_json::Value::Null => {
                std::env::remove_var(key);
                let _ = environ.del_item(key);
            }
            serde_json::Value::String(s) => {
                std::env::set_var(key, s);
                environ.set_item(key, s)?;
            }
            other => {
                let rendered = other.to_string();
                std::env::set_var(key, &rendered);
                environ.set_item(key, rendered)?;
            }
        }
    }
    Ok(())
}

#[pyfunction]
fn encrypt_bytes(partition_id: &str, data: &[u8]) -> PyResult<String> {
    with_manager(|mgr| {
        let json = mgr
            .with_session(partition_id, |session| {
                let drr = session.encrypt(data)?;
                let json =
                    serde_json::to_string(&drr).map_err(|e| anyhow::anyhow!("json error: {e}"))?;
                Ok(json)
            })
            .map_err(anyhow_to_py)?;
        Ok(json)
    })
}

#[pyfunction]
fn encrypt_string(partition_id: &str, text: &str) -> PyResult<String> {
    encrypt_bytes(partition_id, text.as_bytes())
}

#[pyfunction]
fn decrypt_bytes<'py>(
    py: Python<'py>,
    partition_id: &str,
    data_row_record: &str,
) -> PyResult<&'py PyBytes> {
    with_manager(|mgr| {
        let bytes = mgr
            .with_session(partition_id, |session| {
                let drr: ael::types::DataRowRecord = serde_json::from_str(data_row_record)
                    .map_err(|e| anyhow::anyhow!("invalid DataRowRecord JSON: {e}"))?;
                session.decrypt(drr)
            })
            .map_err(anyhow_to_py)?;
        Ok(PyBytes::new(py, &bytes))
    })
}

#[pyfunction]
fn decrypt_string(partition_id: &str, data_row_record: &str) -> PyResult<String> {
    Python::with_gil(|py| {
        let bytes = decrypt_bytes(py, partition_id, data_row_record)?;
        String::from_utf8(bytes.as_bytes().to_vec())
            .map_err(|e| PyRuntimeError::new_err(format!("utf8 error: {e}")))
    })
}

struct FactoryManager {
    factory: Factory,
    sessions: HashMap<String, SessionHandle>,
    enable_session_caching: bool,
}

impl FactoryManager {
    fn new(factory: Factory, applied: config::AppliedConfig) -> Self {
        Self {
            factory,
            sessions: HashMap::new(),
            enable_session_caching: applied.enable_session_caching,
        }
    }

    fn with_session<R>(
        &mut self,
        partition: &str,
        mut f: impl FnMut(&mut SessionHandle) -> anyhow::Result<R>,
    ) -> anyhow::Result<R> {
        if self.enable_session_caching {
            let session = self
                .sessions
                .entry(partition.to_string())
                .or_insert_with(|| self.factory.get_session(partition));
            f(session)
        } else {
            let mut session = self.factory.get_session(partition);
            let result = f(&mut session)?;
            session.close()?;
            Ok(result)
        }
    }

    fn shutdown(mut self) -> anyhow::Result<()> {
        for (_, session) in self.sessions.drain() {
            session.close()?;
        }
        self.factory.close()?;
        Ok(())
    }
}

static MANAGER: Lazy<Mutex<Option<FactoryManager>>> = Lazy::new(|| Mutex::new(None));

fn with_manager<F, R>(f: F) -> PyResult<R>
where
    F: FnOnce(&mut FactoryManager) -> PyResult<R>,
{
    let mut guard = MANAGER.lock().expect("factory mutex poisoned");
    let manager = guard
        .as_mut()
        .ok_or_else(|| PyRuntimeError::new_err("Asherah not configured; call setup()"))?;
    f(manager)
}

#[pyclass(module = "asherah_py", frozen, name = "SessionFactory")]
pub struct PySessionFactory {
    inner: Factory,
}

#[pymethods]
impl PySessionFactory {
    #[new]
    pub fn new() -> PyResult<Self> {
        let inner = ael::builders::factory_from_env().map_err(anyhow_to_py)?;
        Ok(Self { inner })
    }

    #[staticmethod]
    pub fn from_env() -> PyResult<Self> {
        Self::new()
    }

    pub fn get_session(&self, partition_id: &str) -> PyResult<PySession> {
        let session = self.inner.get_session(partition_id);
        Ok(PySession { inner: session })
    }

    pub fn close(&self) -> PyResult<()> {
        self.inner.close().map_err(anyhow_to_py)?;
        Ok(())
    }

    fn __enter__(slf: PyRef<Self>) -> PyResult<PyRef<Self>> {
        Ok(slf)
    }

    fn __exit__(
        &self,
        _ty: Option<&PyAny>,
        _value: Option<&PyAny>,
        _tb: Option<&PyAny>,
    ) -> PyResult<()> {
        self.close()
    }
}

#[pyclass(module = "asherah_py", frozen, name = "Session")]
pub struct PySession {
    inner: SessionHandle,
}

#[pymethods]
impl PySession {
    pub fn encrypt_bytes(&self, data: &[u8]) -> PyResult<String> {
        let drr = self.inner.encrypt(data).map_err(anyhow_to_py)?;
        serde_json::to_string(&drr).map_err(|e| PyRuntimeError::new_err(format!("json error: {e}")))
    }

    pub fn encrypt_text(&self, text: &str) -> PyResult<String> {
        self.encrypt_bytes(text.as_bytes())
    }

    pub fn decrypt_bytes<'py>(
        &self,
        py: Python<'py>,
        data_row_record: &str,
    ) -> PyResult<&'py PyBytes> {
        let pt = self.decrypt_raw(data_row_record)?;
        Ok(PyBytes::new(py, &pt))
    }

    pub fn decrypt_text(&self, data_row_record: &str) -> PyResult<String> {
        let bytes = self.decrypt_raw(data_row_record)?;
        String::from_utf8(bytes).map_err(|e| PyRuntimeError::new_err(format!("utf8 error: {e}")))
    }

    pub fn close(&self) -> PyResult<()> {
        self.inner.close().map_err(anyhow_to_py)?;
        Ok(())
    }

    fn __enter__(slf: PyRef<Self>) -> PyResult<PyRef<Self>> {
        Ok(slf)
    }

    fn __exit__(
        &self,
        _ty: Option<&PyAny>,
        _value: Option<&PyAny>,
        _tb: Option<&PyAny>,
    ) -> PyResult<()> {
        self.close()
    }
}

impl PySession {
    fn decrypt_raw(&self, data_row_record: &str) -> PyResult<Vec<u8>> {
        let drr: ael::types::DataRowRecord =
            serde_json::from_str(data_row_record).map_err(json_parse_err)?;
        self.inner.decrypt(drr).map_err(anyhow_to_py)
    }
}

#[pyfunction]
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[pymodule]
fn asherah_py(py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(setup, m)?)?;
    m.add_function(wrap_pyfunction!(shutdown, m)?)?;
    m.add_function(wrap_pyfunction!(get_setup_status, m)?)?;
    m.add_function(wrap_pyfunction!(setenv, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt_string, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_string, m)?)?;
    m.add_class::<PySessionFactory>()?;
    m.add_class::<PySession>()?;
    m.add_function(wrap_pyfunction!(version, m)?)?;
    py.run(
        r#"
import asyncio as _asyncio

async def setup_async(config):
    loop = _asyncio.get_running_loop()
    return await loop.run_in_executor(None, setup, config)

async def shutdown_async():
    loop = _asyncio.get_running_loop()
    return await loop.run_in_executor(None, shutdown)

async def encrypt_bytes_async(partition_id, data):
    loop = _asyncio.get_running_loop()
    return await loop.run_in_executor(None, encrypt_bytes, partition_id, data)

async def encrypt_string_async(partition_id, text):
    loop = _asyncio.get_running_loop()
    return await loop.run_in_executor(None, encrypt_string, partition_id, text)

async def decrypt_bytes_async(partition_id, data_row_record):
    loop = _asyncio.get_running_loop()
    return await loop.run_in_executor(None, decrypt_bytes, partition_id, data_row_record)

async def decrypt_string_async(partition_id, data_row_record):
    loop = _asyncio.get_running_loop()
    return await loop.run_in_executor(None, decrypt_string, partition_id, data_row_record)
"#,
        None,
        Some(m.dict()),
    )?;
    Ok(())
}
