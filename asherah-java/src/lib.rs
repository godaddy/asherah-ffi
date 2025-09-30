#![allow(non_snake_case)]
#![allow(unsafe_code)]

use std::ptr;

use anyhow::Context;
use asherah as ael;
use asherah_config as config;
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jbyteArray, jlong};
use jni::JNIEnv;
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

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_godaddy_asherah_jni_AsherahNative_factoryFromEnv(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jlong {
    match ael::builders::factory_from_env() {
        Ok(factory) => Box::into_raw(Box::new(factory)) as jlong,
        Err(e) => {
            let _err = env.throw_new(
                "java/lang/RuntimeException",
                format!("factory_from_env failed: {e}"),
            );
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_godaddy_asherah_jni_AsherahNative_factoryFromJson(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    config_json: JString<'_>,
) -> jlong {
    let cfg_str: String = match env.get_string(&config_json) {
        Ok(s) => s.into(),
        Err(e) => {
            let _err = env.throw_new(
                "java/lang/RuntimeException",
                format!("invalid config JSON: {e}"),
            );
            return 0;
        }
    };

    match config::ConfigOptions::from_json(&cfg_str)
        .and_then(|cfg| config::factory_from_config(&cfg))
    {
        Ok((factory, _applied)) => Box::into_raw(Box::new(factory)) as jlong,
        Err(e) => {
            let _err = env.throw_new(
                "java/lang/RuntimeException",
                format!("factory_from_json failed: {e}"),
            );
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_godaddy_asherah_jni_AsherahNative_closeFactory(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    factory_handle: jlong,
) {
    let Some(factory) = (unsafe { from_handle::<Factory>(factory_handle) }) else {
        let _err = env.throw_new("java/lang/RuntimeException", "factory handle is null");
        return;
    };
    if let Err(e) = factory.close() {
        let _err = env.throw_new(
            "java/lang/RuntimeException",
            format!("factory close error: {e}"),
        );
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_godaddy_asherah_jni_AsherahNative_freeFactory(
    _env: JNIEnv<'_>,
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
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    env_json: JString<'_>,
) {
    let payload: String = match env.get_string(&env_json) {
        Ok(s) => s.into(),
        Err(e) => {
            let _err = env.throw_new(
                "java/lang/RuntimeException",
                format!("invalid environment JSON: {e}"),
            );
            return;
        }
    };

    if let Err(e) = apply_env_json(&payload) {
        let _err = env.throw_new("java/lang/RuntimeException", format!("setEnv error: {e}"));
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_godaddy_asherah_jni_AsherahNative_getSession(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    factory_handle: jlong,
    partition_id: JString<'_>,
) -> jlong {
    let Some(factory) = (unsafe { from_handle::<Factory>(factory_handle) }) else {
        let _err = env.throw_new("java/lang/RuntimeException", "factory handle is null");
        return 0;
    };

    let partition: String = match env.get_string(&partition_id) {
        Ok(s) => s.into(),
        Err(e) => {
            let _err = env.throw_new(
                "java/lang/RuntimeException",
                format!("invalid partition id: {e}"),
            );
            return 0;
        }
    };

    let session = factory.get_session(&partition);
    Box::into_raw(Box::new(session)) as jlong
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_godaddy_asherah_jni_AsherahNative_closeSession(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    session_handle: jlong,
) {
    let Some(session) = (unsafe { from_handle::<Session>(session_handle) }) else {
        let _err = env.throw_new("java/lang/RuntimeException", "session handle is null");
        return;
    };
    if let Err(e) = session.close() {
        let _err = env.throw_new(
            "java/lang/RuntimeException",
            format!("session close error: {e}"),
        );
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_godaddy_asherah_jni_AsherahNative_freeSession(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    session_handle: jlong,
) {
    if session_handle != 0 {
        unsafe { drop(Box::from_raw(session_handle as *mut Session)) }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_godaddy_asherah_jni_AsherahNative_encrypt(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    session_handle: jlong,
    plaintext: JByteArray<'_>,
) -> jbyteArray {
    let Some(session) = (unsafe { from_handle::<Session>(session_handle) }) else {
        let _err = env.throw_new("java/lang/RuntimeException", "session handle is null");
        return ptr::null_mut();
    };

    let data = match env.convert_byte_array(plaintext) {
        Ok(d) => d,
        Err(e) => {
            let _err = env.throw_new(
                "java/lang/RuntimeException",
                format!("failed to read plaintext: {e}"),
            );
            return ptr::null_mut();
        }
    };

    let ciphertext = match session.encrypt(&data) {
        Ok(drr) => match serde_json::to_vec(&drr) {
            Ok(bytes) => bytes,
            Err(e) => {
                let _err =
                    env.throw_new("java/lang/RuntimeException", format!("encrypt error: {e}"));
                return ptr::null_mut();
            }
        },
        Err(e) => {
            let _err = env.throw_new("java/lang/RuntimeException", format!("encrypt error: {e}"));
            return ptr::null_mut();
        }
    };

    match env.byte_array_from_slice(&ciphertext) {
        Ok(arr) => arr.into_raw(),
        Err(e) => {
            let _err = env.throw_new(
                "java/lang/RuntimeException",
                format!("failed to create byte array: {e}"),
            );
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_godaddy_asherah_jni_AsherahNative_decrypt(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    session_handle: jlong,
    ciphertext: JByteArray<'_>,
) -> jbyteArray {
    let Some(session) = (unsafe { from_handle::<Session>(session_handle) }) else {
        let _err = env.throw_new("java/lang/RuntimeException", "session handle is null");
        return ptr::null_mut();
    };

    let data = match env.convert_byte_array(ciphertext) {
        Ok(d) => d,
        Err(e) => {
            let _err = env.throw_new(
                "java/lang/RuntimeException",
                format!("failed to read ciphertext: {e}"),
            );
            return ptr::null_mut();
        }
    };

    let result = || -> anyhow::Result<Vec<u8>> {
        let drr: ael::types::DataRowRecord =
            serde_json::from_slice(&data).context("invalid DataRowRecord JSON")?;
        session
            .decrypt(drr)
            .map_err(|e| anyhow::anyhow!("decrypt error: {e}"))
    }();

    let plaintext = match result {
        Ok(pt) => pt,
        Err(e) => {
            let _err = env.throw_new("java/lang/RuntimeException", format!("{e}"));
            return ptr::null_mut();
        }
    };

    match env.byte_array_from_slice(&plaintext) {
        Ok(arr) => arr.into_raw(),
        Err(e) => {
            let _err = env.throw_new(
                "java/lang/RuntimeException",
                format!("failed to create byte array: {e}"),
            );
            ptr::null_mut()
        }
    }
}
