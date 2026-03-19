#![allow(unsafe_code)]
#![allow(unused_qualifications)]

use asherah as ael;
use asherah::logging::{ensure_logger, set_sink as set_log_sink, LogSink};
use asherah::metrics;
use asherah::metrics::MetricsSink;
use asherah_config as config;
use once_cell::sync::Lazy;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::types::PyDict;
use pyo3::PyRef;

use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;

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
fn setup(config_obj: &Bound<'_, PyAny>) -> PyResult<()> {
    let py = config_obj.py();
    let json_module = py.import("json")?;
    let json_config: String = json_module
        .call_method1("dumps", (config_obj,))?
        .extract()?;
    let cfg = config::ConfigOptions::from_json(&json_config).map_err(anyhow_to_py)?;
    let (factory, applied) = config::factory_from_config(&cfg).map_err(anyhow_to_py)?;
    let mut guard = MANAGER.lock();
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
    let mut guard = MANAGER.lock();
    if let Some(manager) = guard.take() {
        manager.shutdown().map_err(anyhow_to_py)?;
    }
    Ok(())
}

#[pyfunction]
fn get_setup_status() -> PyResult<bool> {
    let guard = MANAGER.lock();
    Ok(guard.is_some())
}

#[pyfunction]
fn setenv(env_obj: &Bound<'_, PyAny>) -> PyResult<()> {
    let py = env_obj.py();
    let value = match env_obj.extract::<String>() {
        Ok(s) => serde_json::from_str::<serde_json::Value>(&s)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?,
        Err(_) => {
            let json_module = py.import("json")?;
            let dumped: String = json_module.call_method1("dumps", (env_obj,))?.extract()?;
            serde_json::from_str::<serde_json::Value>(&dumped)
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?
        }
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
                let _removed = environ.del_item(key);
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
    let session = with_manager(|mgr| Ok(mgr.get_or_create_session(partition_id)))?;
    let drr = session.encrypt(data).map_err(anyhow_to_py)?;
    let json = serde_json::to_string(&drr)
        .map_err(|e| PyRuntimeError::new_err(format!("json error: {e}")))?;
    Ok(json)
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
) -> PyResult<Bound<'py, PyBytes>> {
    let session = with_manager(|mgr| Ok(mgr.get_or_create_session(partition_id)))?;
    let drr: ael::types::DataRowRecord = serde_json::from_str(data_row_record)
        .map_err(|e| PyRuntimeError::new_err(format!("invalid DataRowRecord JSON: {e}")))?;
    let bytes = session.decrypt(drr).map_err(anyhow_to_py)?;
    Ok(PyBytes::new(py, &bytes))
}

#[pyfunction]
fn decrypt_string(partition_id: &str, data_row_record: &str) -> PyResult<String> {
    Python::attach(|py| {
        let bytes = decrypt_bytes(py, partition_id, data_row_record)?;
        String::from_utf8(bytes.as_bytes().to_vec())
            .map_err(|e| PyRuntimeError::new_err(format!("utf8 error: {e}")))
    })
}

struct FactoryManager {
    factory: Arc<Factory>,
    sessions: Mutex<HashMap<String, Arc<SessionHandle>>>,
    enable_session_caching: bool,
    session_cache_max: usize,
}

impl FactoryManager {
    fn new(factory: Factory, applied: config::AppliedConfig) -> Self {
        Self {
            factory: Arc::new(factory),
            sessions: Mutex::new(HashMap::new()),
            enable_session_caching: applied.enable_session_caching,
            session_cache_max: 1000,
        }
    }

    fn get_or_create_session(&self, partition: &str) -> Arc<SessionHandle> {
        if self.enable_session_caching {
            let mut sessions = self.sessions.lock();
            let session = sessions
                .entry(partition.to_string())
                .or_insert_with(|| Arc::new(self.factory.get_session(partition)))
                .clone();
            // Evict oldest if over limit
            while sessions.len() > self.session_cache_max {
                if let Some(key) = sessions.keys().next().cloned() {
                    sessions.remove(&key);
                }
            }
            session
            // Lock dropped here — crypto runs outside
        } else {
            Arc::new(self.factory.get_session(partition))
        }
    }

    fn shutdown(self) -> anyhow::Result<()> {
        let sessions = self.sessions.into_inner();
        drop(sessions); // drop all Arc<SessionHandle>
                        // Factory is in an Arc; it's dropped when the last reference goes away
        if let Some(factory) = Arc::into_inner(self.factory) {
            factory.close()?;
        }
        Ok(())
    }
}

static MANAGER: Lazy<Mutex<Option<FactoryManager>>> = Lazy::new(|| Mutex::new(None));
static PY_METRICS_CALLBACK: Lazy<Mutex<Option<Arc<Py<PyAny>>>>> = Lazy::new(|| Mutex::new(None));
static PY_LOG_CALLBACK: Lazy<Mutex<Option<Arc<Py<PyAny>>>>> = Lazy::new(|| Mutex::new(None));

fn with_manager<F, R>(f: F) -> PyResult<R>
where
    F: FnOnce(&FactoryManager) -> PyResult<R>,
{
    let guard = MANAGER.lock();
    let manager = guard
        .as_ref()
        .ok_or_else(|| PyRuntimeError::new_err("Asherah not configured; call setup()"))?;
    f(manager)
}

#[pyclass(module = "asherah", frozen, name = "SessionFactory")]
#[allow(missing_debug_implementations)]
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

    fn __enter__(slf: PyRef<'_, Self>) -> PyResult<PyRef<'_, Self>> {
        Ok(slf)
    }

    fn __exit__(
        &self,
        _ty: Option<&Bound<'_, PyAny>>,
        _value: Option<&Bound<'_, PyAny>>,
        _tb: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        self.close()
    }
}

#[pyclass(module = "asherah", frozen, name = "Session")]
#[allow(missing_debug_implementations)]
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
    ) -> PyResult<Bound<'py, PyBytes>> {
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

    fn __enter__(slf: PyRef<'_, Self>) -> PyResult<PyRef<'_, Self>> {
        Ok(slf)
    }

    fn __exit__(
        &self,
        _ty: Option<&Bound<'_, PyAny>>,
        _value: Option<&Bound<'_, PyAny>>,
        _tb: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        self.close()
    }

    fn decrypt_raw(&self, data_row_record: &str) -> PyResult<Vec<u8>> {
        let drr: ael::types::DataRowRecord =
            serde_json::from_str(data_row_record).map_err(json_parse_err)?;
        self.inner.decrypt(drr).map_err(anyhow_to_py)
    }
}

struct PyMetricsSink {
    callback: Arc<Py<PyAny>>,
}

impl PyMetricsSink {
    fn emit(&self, builder: impl FnOnce(Python<'_>) -> PyResult<Py<PyAny>>) {
        let cb = Arc::clone(&self.callback);
        Python::attach(|py| match builder(py) {
            Ok(obj) => {
                if let Err(err) = cb.call1(py, (obj,)) {
                    err.print(py);
                }
            }
            Err(err) => err.print(py),
        });
    }
}

impl MetricsSink for PyMetricsSink {
    fn encrypt(&self, duration: std::time::Duration) {
        self.emit(|py| {
            let dict = PyDict::new(py);
            dict.set_item("type", "encrypt")?;
            dict.set_item("duration_ns", duration.as_nanos() as u64)?;
            Ok(dict.into_any().unbind())
        });
    }

    fn decrypt(&self, duration: std::time::Duration) {
        self.emit(|py| {
            let dict = PyDict::new(py);
            dict.set_item("type", "decrypt")?;
            dict.set_item("duration_ns", duration.as_nanos() as u64)?;
            Ok(dict.into_any().unbind())
        });
    }

    fn store(&self, duration: std::time::Duration) {
        self.emit(|py| {
            let dict = PyDict::new(py);
            dict.set_item("type", "store")?;
            dict.set_item("duration_ns", duration.as_nanos() as u64)?;
            Ok(dict.into_any().unbind())
        });
    }

    fn load(&self, duration: std::time::Duration) {
        self.emit(|py| {
            let dict = PyDict::new(py);
            dict.set_item("type", "load")?;
            dict.set_item("duration_ns", duration.as_nanos() as u64)?;
            Ok(dict.into_any().unbind())
        });
    }

    fn cache_hit(&self, name: &str) {
        let name = name.to_string();
        self.emit(|py| {
            let dict = PyDict::new(py);
            dict.set_item("type", "cache_hit")?;
            dict.set_item("name", &name)?;
            Ok(dict.into_any().unbind())
        });
    }

    fn cache_miss(&self, name: &str) {
        let name = name.to_string();
        self.emit(|py| {
            let dict = PyDict::new(py);
            dict.set_item("type", "cache_miss")?;
            dict.set_item("name", &name)?;
            Ok(dict.into_any().unbind())
        });
    }
}

struct PyLogSink {
    callback: Arc<Py<PyAny>>,
}

impl LogSink for PyLogSink {
    fn log(&self, record: &log::Record<'_>) {
        let level = record.level().to_string();
        let message = record.args().to_string();
        let target = record.target().to_string();
        let cb = Arc::clone(&self.callback);
        Python::attach(|py| {
            let dict = PyDict::new(py);
            if dict.set_item("level", &level).is_err()
                || dict.set_item("message", &message).is_err()
                || dict.set_item("target", &target).is_err()
            {
                return;
            }
            if let Err(err) = cb.call1(py, (&dict,)) {
                err.print(py);
            }
        });
    }
}

#[pyfunction]
fn set_metrics_hook(callback: Option<&Bound<'_, PyAny>>) -> PyResult<()> {
    if let Some(cb) = callback {
        let obj: Py<PyAny> = cb.clone().unbind();
        let arc = Arc::new(obj);
        metrics::set_sink(PyMetricsSink {
            callback: Arc::clone(&arc),
        });
        *PY_METRICS_CALLBACK.lock() = Some(arc);
    } else {
        metrics::clear_sink();
        *PY_METRICS_CALLBACK.lock() = None;
    }
    Ok(())
}

#[pyfunction]
fn set_log_hook(callback: Option<&Bound<'_, PyAny>>) -> PyResult<()> {
    ensure_logger().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    if let Some(cb) = callback {
        let obj: Py<PyAny> = cb.clone().unbind();
        let arc = Arc::new(obj);
        set_log_sink(
            "python",
            Some(Arc::new(PyLogSink {
                callback: Arc::clone(&arc),
            })),
        );
        *PY_LOG_CALLBACK.lock() = Some(arc);
    } else {
        set_log_sink("python", None);
        *PY_LOG_CALLBACK.lock() = None;
    }
    Ok(())
}

#[pyfunction]
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[pymodule]
fn _asherah(m: &Bound<'_, PyModule>) -> PyResult<()> {
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
    m.add_function(wrap_pyfunction!(set_metrics_hook, m)?)?;
    m.add_function(wrap_pyfunction!(set_log_hook, m)?)?;
    m.add_function(wrap_pyfunction!(version, m)?)?;
    let py = m.py();
    let dict = m.dict();
    py.run(
        cr#"
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
        Some(&dict),
    )?;
    Ok(())
}
