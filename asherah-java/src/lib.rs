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
        Ok(Box::into_raw(Box::new(session)) as jlong)
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
        let session = unsafe { from_handle::<Session>(session_handle) }
            .ok_or_else(|| throw_err(env, "session handle is null"))?;
        session
            .close()
            .map_err(|e| throw_err(env, format_args!("session close error: {e:#}")))?;
        Ok(())
    })
    .resolve::<ThrowRuntimeExAndDefault>();
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_godaddy_asherah_jni_AsherahNative_freeSession(
    _env: EnvUnowned<'_>,
    _class: JClass<'_>,
    session_handle: jlong,
) {
    if session_handle != 0 {
        unsafe { drop(Box::from_raw(session_handle as *mut Session)) }
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
        let session = unsafe { from_handle::<Session>(session_handle) }
            .ok_or_else(|| throw_err(env, "session handle is null"))?;
        let data = env.convert_byte_array(&plaintext)?;
        let drr = session
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
        let session = unsafe { from_handle::<Session>(session_handle) }
            .ok_or_else(|| throw_err(env, "session handle is null"))?;
        let data = env.convert_byte_array(&ciphertext)?;
        let drr: ael::types::DataRowRecord = serde_json::from_slice(&data)
            .map_err(|e| throw_err(env, format_args!("invalid DataRowRecord JSON: {e}")))?;
        let plaintext = session
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
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_godaddy_asherah_jni_AsherahNative_encryptAsync<'caller>(
    mut env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    session_handle: jlong,
    plaintext: JByteArray<'caller>,
    future: JObject<'caller>,
) {
    env.with_env(|env| -> jni::errors::Result<()> {
        let session = unsafe { from_handle::<Session>(session_handle) }
            .ok_or_else(|| throw_err(env, "session handle is null"))?;
        let data = env.convert_byte_array(&plaintext)?;
        let jvm = env.get_java_vm()?;
        let future_ref = env.new_global_ref(&future)?;
        let session_ptr: *const Session = session;
        let session_addr = session_ptr as usize;

        ASYNC_RT.spawn(async move {
            let session = unsafe { &*(session_addr as *const Session) };
            let result = match session.encrypt_async(&data).await {
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
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_godaddy_asherah_jni_AsherahNative_decryptAsync<'caller>(
    mut env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    session_handle: jlong,
    ciphertext: JByteArray<'caller>,
    future: JObject<'caller>,
) {
    env.with_env(|env| -> jni::errors::Result<()> {
        let session = unsafe { from_handle::<Session>(session_handle) }
            .ok_or_else(|| throw_err(env, "session handle is null"))?;
        let data = env.convert_byte_array(&ciphertext)?;
        let jvm = env.get_java_vm()?;
        let future_ref = env.new_global_ref(&future)?;
        let session_ptr: *const Session = session;
        let session_addr = session_ptr as usize;

        ASYNC_RT.spawn(async move {
            let session = unsafe { &*(session_addr as *const Session) };
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
            let result = session.decrypt_async(drr).await;
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
