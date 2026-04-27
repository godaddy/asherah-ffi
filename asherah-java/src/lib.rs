#![allow(non_snake_case)]
#![allow(unsafe_code)]

use anyhow::Context;
use asherah as ael;
use asherah_config as config;
use jni::errors::ThrowRuntimeExAndDefault;
use jni::objects::{JByteArray, JClass, JObject, JString};
use jni::strings::JNIString;
use jni::sys::jlong;
use jni::{EnvUnowned, JavaVM};
use once_cell::sync::Lazy;
use serde_json::{self, Value};
use std::sync::Arc;

type Factory = ael::session::PublicFactory<
    ael::aead::AES256GCM,
    ael::builders::DynKms,
    ael::builders::DynMetastore,
>;
type Session = ael::session::PublicSession<
    ael::aead::AES256GCM,
    ael::builders::DynKms,
    ael::builders::DynMetastore,
>;

/// Shared session handle. Wraps `Arc<Session>` so async tokio tasks can hold
/// an owned reference that outlives a premature `freeSession` call.
struct SharedJniSession {
    session: Arc<Session>,
}

unsafe fn from_handle<'handle, T>(handle: jlong) -> Option<&'handle T> {
    (handle as *const T).as_ref()
}

/// Throw a RuntimeException with the given message and return `Error::JavaException`.
fn throw_err(env: &mut jni::Env<'_>, msg: impl std::fmt::Display) -> jni::errors::Error {
    drop(env.throw_new(
        JNIString::from("java/lang/RuntimeException"),
        JNIString::from(msg.to_string()),
    ));
    jni::errors::Error::JavaException
}

#[allow(deprecated)]
fn get_jstring(env: &mut jni::Env<'_>, s: &JString<'_>) -> jni::errors::Result<String> {
    let chars = env.get_string(s)?;
    Ok(chars.into())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_godaddy_asherah_jni_AsherahNative_factoryFromEnv(
    mut env: EnvUnowned<'_>,
    _class: JClass<'_>,
) -> jlong {
    env.with_env(|env| -> jni::errors::Result<jlong> {
        let factory = ael::builders::factory_from_env()
            .map_err(|e| throw_err(env, format_args!("factory_from_env failed: {e:#}")))?;
        // Always enable per-factory metrics so an installed metrics hook
        // (setMetricsHook) actually fires for encrypt/decrypt/store/load
        // events. The cost is one Instant::now() per encrypt regardless;
        // the global metrics gate (toggled by setMetricsHook) decides
        // whether the sink is invoked.
        let factory = factory.with_metrics(true);
        Ok(Box::into_raw(Box::new(factory)) as jlong)
    })
    .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_godaddy_asherah_jni_AsherahNative_factoryFromJson(
    mut env: EnvUnowned<'_>,
    _class: JClass<'_>,
    config_json: JString<'_>,
) -> jlong {
    env.with_env(|env| -> jni::errors::Result<jlong> {
        let cfg_str = get_jstring(env, &config_json)?;
        let (factory, _applied) = config::ConfigOptions::from_json(&cfg_str)
            .and_then(|cfg| config::factory_from_config(&cfg))
            .map_err(|e| throw_err(env, format_args!("factory_from_json failed: {e:#}")))?;
        let factory = factory.with_metrics(true);
        Ok(Box::into_raw(Box::new(factory)) as jlong)
    })
    .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_godaddy_asherah_jni_AsherahNative_closeFactory(
    mut env: EnvUnowned<'_>,
    _class: JClass<'_>,
    factory_handle: jlong,
) {
    env.with_env(|env| -> jni::errors::Result<()> {
        let factory = unsafe { from_handle::<Factory>(factory_handle) }
            .ok_or_else(|| throw_err(env, "factory handle is null"))?;
        factory
            .close()
            .map_err(|e| throw_err(env, format_args!("factory close error: {e:#}")))?;
        Ok(())
    })
    .resolve::<ThrowRuntimeExAndDefault>();
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_godaddy_asherah_jni_AsherahNative_freeFactory(
    _env: EnvUnowned<'_>,
    _class: JClass<'_>,
    factory_handle: jlong,
) {
    if factory_handle != 0 {
        unsafe {
            drop(Box::from_raw(factory_handle as *mut Factory));
        }
    }
}

fn apply_env_json(payload: &str) -> anyhow::Result<()> {
    let value: Value = serde_json::from_str(payload).context("invalid environment JSON")?;
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("environment payload must be an object"))?;
    for (key, val) in obj {
        if val.is_null() {
            std::env::remove_var(key);
            continue;
        }
        let as_str = if let Some(s) = val.as_str() {
            s.to_string()
        } else {
            val.to_string()
        };
        std::env::set_var(key, as_str);
    }
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_godaddy_asherah_jni_AsherahNative_setEnv(
    mut env: EnvUnowned<'_>,
    _class: JClass<'_>,
    env_json: JString<'_>,
) {
    env.with_env(|env| -> jni::errors::Result<()> {
        let payload = get_jstring(env, &env_json)?;
        apply_env_json(&payload)
            .map_err(|e| throw_err(env, format_args!("setEnv error: {e:#}")))?;
        Ok(())
    })
    .resolve::<ThrowRuntimeExAndDefault>();
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_godaddy_asherah_jni_AsherahNative_getSession(
    mut env: EnvUnowned<'_>,
    _class: JClass<'_>,
    factory_handle: jlong,
    partition_id: JString<'_>,
) -> jlong {
    env.with_env(|env| -> jni::errors::Result<jlong> {
        let factory = unsafe { from_handle::<Factory>(factory_handle) }
            .ok_or_else(|| throw_err(env, "factory handle is null"))?;
        let partition = get_jstring(env, &partition_id)?;
        let session = factory.get_session(&partition);
        let shared = SharedJniSession {
            session: Arc::new(session),
        };
        Ok(Box::into_raw(Box::new(shared)) as jlong)
    })
    .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_godaddy_asherah_jni_AsherahNative_closeSession(
    mut env: EnvUnowned<'_>,
    _class: JClass<'_>,
    session_handle: jlong,
) {
    env.with_env(|env| -> jni::errors::Result<()> {
        let shared = unsafe { from_handle::<SharedJniSession>(session_handle) }
            .ok_or_else(|| throw_err(env, "session handle is null"))?;
        shared
            .session
            .close()
            .map_err(|e| throw_err(env, format_args!("session close error: {e:#}")))?;
        Ok(())
    })
    .resolve::<ThrowRuntimeExAndDefault>();
}

/// Free the caller's session handle. If async tasks still hold Arc clones,
/// the underlying session remains alive until those tasks complete.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_godaddy_asherah_jni_AsherahNative_freeSession(
    _env: EnvUnowned<'_>,
    _class: JClass<'_>,
    session_handle: jlong,
) {
    if session_handle != 0 {
        unsafe { drop(Box::from_raw(session_handle as *mut SharedJniSession)) }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_godaddy_asherah_jni_AsherahNative_encrypt<'caller>(
    mut env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    session_handle: jlong,
    plaintext: JByteArray<'caller>,
) -> JByteArray<'caller> {
    env.with_env(|env| -> jni::errors::Result<JByteArray<'caller>> {
        let shared = unsafe { from_handle::<SharedJniSession>(session_handle) }
            .ok_or_else(|| throw_err(env, "session handle is null"))?;
        let data = env.convert_byte_array(&plaintext)?;
        let drr = shared
            .session
            .encrypt(&data)
            .map_err(|e| throw_err(env, format_args!("encrypt error: {e:#}")))?;
        let ciphertext = serde_json::to_vec(&drr)
            .map_err(|e| throw_err(env, format_args!("encrypt serialization error: {e:#}")))?;
        let arr = env.byte_array_from_slice(&ciphertext)?;
        Ok(arr)
    })
    .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_godaddy_asherah_jni_AsherahNative_decrypt<'caller>(
    mut env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    session_handle: jlong,
    ciphertext: JByteArray<'caller>,
) -> JByteArray<'caller> {
    env.with_env(|env| -> jni::errors::Result<JByteArray<'caller>> {
        let shared = unsafe { from_handle::<SharedJniSession>(session_handle) }
            .ok_or_else(|| throw_err(env, "session handle is null"))?;
        let data = env.convert_byte_array(&ciphertext)?;
        let drr: ael::types::DataRowRecord = serde_json::from_slice(&data)
            .map_err(|e| throw_err(env, format_args!("invalid DataRowRecord JSON: {e}")))?;
        let plaintext = shared
            .session
            .decrypt(drr)
            .map_err(|e| throw_err(env, format_args!("decrypt error: {e:#}")))?;
        let arr = env.byte_array_from_slice(&plaintext)?;
        Ok(arr)
    })
    .resolve::<ThrowRuntimeExAndDefault>()
}

// ── Async JNI ────────────────────────────────────────────────────────

static ASYNC_RT: Lazy<tokio::runtime::Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("asherah-java-async")
        .enable_all()
        .build()
        .expect("failed to create async JNI tokio runtime")
});

/// Async encrypt. Accepts a CompletableFuture<byte[]> and completes it on a tokio worker thread.
/// The session is kept alive by an Arc clone until the async operation completes.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_godaddy_asherah_jni_AsherahNative_encryptAsync<'caller>(
    mut env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    session_handle: jlong,
    plaintext: JByteArray<'caller>,
    future: JObject<'caller>,
) {
    env.with_env(|env| -> jni::errors::Result<()> {
        let shared = unsafe { from_handle::<SharedJniSession>(session_handle) }
            .ok_or_else(|| throw_err(env, "session handle is null"))?;
        let data = env.convert_byte_array(&plaintext)?;
        let jvm = env.get_java_vm()?;
        let future_ref = env.new_global_ref(&future)?;
        let session_arc = Arc::clone(&shared.session);

        ASYNC_RT.spawn(async move {
            let result = match session_arc.encrypt_async(&data).await {
                Ok(drr) => serde_json::to_vec(&drr).map_err(|e| anyhow::anyhow!("{e:#}")),
                Err(e) => Err(e),
            };
            complete_java_future(&jvm, &future_ref, result);
        });
        Ok(())
    })
    .resolve::<ThrowRuntimeExAndDefault>();
}

/// Async decrypt. Accepts a CompletableFuture<byte[]> and completes it on a tokio worker thread.
/// The session is kept alive by an Arc clone until the async operation completes.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_godaddy_asherah_jni_AsherahNative_decryptAsync<'caller>(
    mut env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    session_handle: jlong,
    ciphertext: JByteArray<'caller>,
    future: JObject<'caller>,
) {
    env.with_env(|env| -> jni::errors::Result<()> {
        let shared = unsafe { from_handle::<SharedJniSession>(session_handle) }
            .ok_or_else(|| throw_err(env, "session handle is null"))?;
        let data = env.convert_byte_array(&ciphertext)?;
        let jvm = env.get_java_vm()?;
        let future_ref = env.new_global_ref(&future)?;
        let session_arc = Arc::clone(&shared.session);

        ASYNC_RT.spawn(async move {
            let drr = match serde_json::from_slice::<ael::types::DataRowRecord>(&data) {
                Ok(d) => d,
                Err(e) => {
                    complete_java_future(
                        &jvm,
                        &future_ref,
                        Err(anyhow::anyhow!("invalid DataRowRecord JSON: {e}")),
                    );
                    return;
                }
            };
            let result = session_arc.decrypt_async(drr).await;
            complete_java_future(&jvm, &future_ref, result);
        });
        Ok(())
    })
    .resolve::<ThrowRuntimeExAndDefault>();
}

/// Complete a Java CompletableFuture<byte[]> from a tokio worker thread.
fn complete_java_future(
    jvm: &JavaVM,
    future_ref: &jni::objects::Global<JObject<'static>>,
    result: Result<Vec<u8>, anyhow::Error>,
) {
    let jni_result: Result<(), jni::errors::Error> =
        jvm.attach_current_thread(|env| -> Result<(), jni::errors::Error> {
            let complete_sig =
                jni::signature::RuntimeMethodSignature::from_str("(Ljava/lang/Object;)Z")?;
            let except_sig =
                jni::signature::RuntimeMethodSignature::from_str("(Ljava/lang/Throwable;)Z")?;
            let rt_ctor_sig =
                jni::signature::RuntimeMethodSignature::from_str("(Ljava/lang/String;)V")?;
            match result {
                Ok(ref bytes) => {
                    let byte_array = env.byte_array_from_slice(bytes)?;
                    env.call_method(
                        future_ref.as_obj(),
                        JNIString::from("complete"),
                        complete_sig.method_signature(),
                        &[jni::objects::JValue::Object(&byte_array.into())],
                    )?;
                }
                Err(ref e) => {
                    let msg = e.to_string();
                    let jmsg = env.new_string(&msg)?;
                    let exception = env.new_object(
                        JNIString::from("java/lang/RuntimeException"),
                        rt_ctor_sig.method_signature(),
                        &[jni::objects::JValue::Object(&jmsg.into())],
                    )?;
                    env.call_method(
                        future_ref.as_obj(),
                        JNIString::from("completeExceptionally"),
                        except_sig.method_signature(),
                        &[jni::objects::JValue::Object(&exception)],
                    )?;
                }
            }
            Ok(())
        });
    if let Err(e) = jni_result {
        log::error!("failed to complete Java future: {e}");
    }
}

// =====================================================================
// Log + metrics hooks
//
// The Java side passes a functional-interface object (AsherahLogHook /
// AsherahMetricsHook). We hold a JavaVM handle plus a global reference
// to the callback object; on each event we attach the current thread,
// build the event POJO, invoke the callback, and detach.
//
// The callback may fire from any thread (Rust tokio worker threads,
// DB driver threads). attach_current_thread is required for non-JNI
// threads. Callbacks that throw are caught — propagating an exception
// across the FFI boundary is undefined behavior.
// =====================================================================

use asherah::logging::{ensure_logger, set_sink as set_log_sink, LogSink};
use asherah::metrics::{self, MetricsSink};
use parking_lot::Mutex as PMutex;
use std::cell::Cell;

struct JavaHook {
    jvm: JavaVM,
    callback: jni::objects::Global<JObject<'static>>,
}

static JAVA_LOG_HOOK: Lazy<PMutex<Option<Arc<JavaHook>>>> = Lazy::new(|| PMutex::new(None));
static JAVA_METRICS_HOOK: Lazy<PMutex<Option<Arc<JavaHook>>>> = Lazy::new(|| PMutex::new(None));

// Re-entrancy guard. The `jni` crate itself logs at trace level from inside
// our `new_string` / `new_object` / `call_method` calls. Without this guard
// our LogSink would recursively dispatch into itself and the JVM would crash
// because nested JNI work runs in the wrong stack frame.
thread_local! {
    static IN_LOG_SINK: Cell<bool> = const { Cell::new(false) };
    static IN_METRICS_SINK: Cell<bool> = const { Cell::new(false) };
}

struct JavaLogSink;
struct JavaMetricsSink;

impl LogSink for JavaLogSink {
    fn log(&self, record: &log::Record<'_>) {
        // Filter out jni's own internal trace/debug spam — every JNI call
        // we make from inside the sink would otherwise re-enter here.
        if record.target().starts_with("jni") {
            return;
        }
        if IN_LOG_SINK.with(|f| f.replace(true)) {
            // Already inside the sink on this thread — drop to avoid recursion.
            return;
        }
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                IN_LOG_SINK.with(|f| f.set(false));
            }
        }
        let _reset = Reset;
        let hook = match JAVA_LOG_HOOK.lock().as_ref() {
            Some(h) => Arc::clone(h),
            None => return,
        };
        let level = match record.level() {
            log::Level::Error => "error",
            log::Level::Warn => "warn",
            log::Level::Info => "info",
            log::Level::Debug => "debug",
            log::Level::Trace => "trace",
        };
        let target = record.target().to_string();
        let message = record.args().to_string();
        drop(
            hook.jvm
                .attach_current_thread(|env| -> jni::errors::Result<()> {
                    let log_event_class =
                        env.find_class(JNIString::from("com/godaddy/asherah/jni/LogEvent"))?;
                    let level_jstr = env.new_string(level)?;
                    let target_jstr = env.new_string(&target)?;
                    let message_jstr = env.new_string(&message)?;
                    let ctor_sig = jni::signature::RuntimeMethodSignature::from_str(
                        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
                    )?;
                    let event = env.new_object(
                        log_event_class,
                        ctor_sig.method_signature(),
                        &[
                            jni::objects::JValue::Object(&level_jstr.into()),
                            jni::objects::JValue::Object(&target_jstr.into()),
                            jni::objects::JValue::Object(&message_jstr.into()),
                        ],
                    )?;
                    let on_log_sig = jni::signature::RuntimeMethodSignature::from_str(
                        "(Lcom/godaddy/asherah/jni/LogEvent;)V",
                    )?;
                    drop(env.call_method(
                        hook.callback.as_obj(),
                        JNIString::from("onLog"),
                        on_log_sig.method_signature(),
                        &[jni::objects::JValue::Object(&event)],
                    ));
                    // Swallow any exception thrown by the user's onLog so we
                    // never propagate across the FFI boundary.
                    if env.exception_check() {
                        env.exception_clear();
                    }
                    Ok(())
                }),
        );
    }
}

impl JavaMetricsSink {
    fn emit(&self, event_type: &str, duration_ns: u64, name: Option<&str>) {
        if IN_METRICS_SINK.with(|f| f.replace(true)) {
            return;
        }
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                IN_METRICS_SINK.with(|f| f.set(false));
            }
        }
        let _reset = Reset;
        let hook = match JAVA_METRICS_HOOK.lock().as_ref() {
            Some(h) => Arc::clone(h),
            None => return,
        };
        let owned_name = name.map(|s| s.to_string());
        drop(
            hook.jvm
                .attach_current_thread(|env| -> jni::errors::Result<()> {
                    let event_class =
                        env.find_class(JNIString::from("com/godaddy/asherah/jni/MetricsEvent"))?;
                    let type_jstr = env.new_string(event_type)?;
                    let name_jstr = match owned_name.as_deref() {
                        Some(n) => env.new_string(n)?.into(),
                        None => JObject::null(),
                    };
                    let ctor_sig = jni::signature::RuntimeMethodSignature::from_str(
                        "(Ljava/lang/String;JLjava/lang/String;)V",
                    )?;
                    let event = env.new_object(
                        event_class,
                        ctor_sig.method_signature(),
                        &[
                            jni::objects::JValue::Object(&type_jstr.into()),
                            jni::objects::JValue::Long(duration_ns as i64),
                            jni::objects::JValue::Object(&name_jstr),
                        ],
                    )?;
                    let on_metric_sig = jni::signature::RuntimeMethodSignature::from_str(
                        "(Lcom/godaddy/asherah/jni/MetricsEvent;)V",
                    )?;
                    drop(env.call_method(
                        hook.callback.as_obj(),
                        JNIString::from("onMetric"),
                        on_metric_sig.method_signature(),
                        &[jni::objects::JValue::Object(&event)],
                    ));
                    if env.exception_check() {
                        env.exception_clear();
                    }
                    Ok(())
                }),
        );
    }
}

impl MetricsSink for JavaMetricsSink {
    fn encrypt(&self, dur: std::time::Duration) {
        self.emit("encrypt", dur.as_nanos() as u64, None);
    }
    fn decrypt(&self, dur: std::time::Duration) {
        self.emit("decrypt", dur.as_nanos() as u64, None);
    }
    fn store(&self, dur: std::time::Duration) {
        self.emit("store", dur.as_nanos() as u64, None);
    }
    fn load(&self, dur: std::time::Duration) {
        self.emit("load", dur.as_nanos() as u64, None);
    }
    fn cache_hit(&self, name: &str) {
        self.emit("cache_hit", 0, Some(name));
    }
    fn cache_miss(&self, name: &str) {
        self.emit("cache_miss", 0, Some(name));
    }
    fn cache_stale(&self, name: &str) {
        self.emit("cache_stale", 0, Some(name));
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_godaddy_asherah_jni_AsherahNative_setLogHook(
    mut env: EnvUnowned<'_>,
    _class: JClass<'_>,
    callback: JObject<'_>,
) {
    env.with_env(|env| -> jni::errors::Result<()> {
        if callback.is_null() {
            // Treat null as clear — same semantics as clearLogHook.
            *JAVA_LOG_HOOK.lock() = None;
            set_log_sink("java", None);
            return Ok(());
        }
        let jvm = env.get_java_vm()?;
        let global = env.new_global_ref(&callback)?;
        ensure_logger().map_err(|_| jni::errors::Error::JavaException)?;
        *JAVA_LOG_HOOK.lock() = Some(Arc::new(JavaHook {
            jvm,
            callback: global,
        }));
        set_log_sink("java", Some(Arc::new(JavaLogSink)));
        Ok(())
    })
    .resolve::<ThrowRuntimeExAndDefault>();
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_godaddy_asherah_jni_AsherahNative_clearLogHook(
    _env: EnvUnowned<'_>,
    _class: JClass<'_>,
) {
    *JAVA_LOG_HOOK.lock() = None;
    set_log_sink("java", None);
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_godaddy_asherah_jni_AsherahNative_setMetricsHook(
    mut env: EnvUnowned<'_>,
    _class: JClass<'_>,
    callback: JObject<'_>,
) {
    env.with_env(|env| -> jni::errors::Result<()> {
        if callback.is_null() {
            *JAVA_METRICS_HOOK.lock() = None;
            metrics::clear_sink();
            metrics::set_enabled(false);
            return Ok(());
        }
        let jvm = env.get_java_vm()?;
        let global = env.new_global_ref(&callback)?;
        *JAVA_METRICS_HOOK.lock() = Some(Arc::new(JavaHook {
            jvm,
            callback: global,
        }));
        metrics::set_sink(JavaMetricsSink);
        metrics::set_enabled(true);
        Ok(())
    })
    .resolve::<ThrowRuntimeExAndDefault>();
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_godaddy_asherah_jni_AsherahNative_clearMetricsHook(
    _env: EnvUnowned<'_>,
    _class: JClass<'_>,
) {
    *JAVA_METRICS_HOOK.lock() = None;
    metrics::clear_sink();
    metrics::set_enabled(false);
}
