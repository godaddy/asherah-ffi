#![allow(non_snake_case)]

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

unsafe fn from_handle<'a, T>(handle: jlong) -> Option<&'a T> {
    (handle as *const T).as_ref()
}

#[no_mangle]
pub extern "system" fn Java_com_godaddy_asherah_jni_AsherahNative_factoryFromEnv(
    mut env: JNIEnv,
    _class: JClass,
) -> jlong {
    match ael::builders::factory_from_env() {
        Ok(factory) => Box::into_raw(Box::new(factory)) as jlong,
        Err(e) => {
            let _ = env.throw_new(
                "java/lang/RuntimeException",
                format!("factory_from_env failed: {e}"),
            );
            0
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_godaddy_asherah_jni_AsherahNative_factoryFromJson(
    mut env: JNIEnv,
    _class: JClass,
    config_json: JString,
) -> jlong {
    let cfg_str: String = match env.get_string(&config_json) {
        Ok(s) => s.into(),
        Err(e) => {
            let _ = env.throw_new(
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
            let _ = env.throw_new(
                "java/lang/RuntimeException",
                format!("factory_from_json failed: {e}"),
            );
            0
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_godaddy_asherah_jni_AsherahNative_closeFactory(
    mut env: JNIEnv,
    _class: JClass,
    factory_handle: jlong,
) {
    let Some(factory) = (unsafe { from_handle::<Factory>(factory_handle) }) else {
        let _ = env.throw_new("java/lang/RuntimeException", "factory handle is null");
        return;
    };
    if let Err(e) = factory.close() {
        let _ = env.throw_new(
            "java/lang/RuntimeException",
            format!("factory close error: {e}"),
        );
    }
}

#[no_mangle]
pub extern "system" fn Java_com_godaddy_asherah_jni_AsherahNative_freeFactory(
    _env: JNIEnv,
    _class: JClass,
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

#[no_mangle]
pub extern "system" fn Java_com_godaddy_asherah_jni_AsherahNative_setEnv(
    mut env: JNIEnv,
    _class: JClass,
    env_json: JString,
) {
    let payload: String = match env.get_string(&env_json) {
        Ok(s) => s.into(),
        Err(e) => {
            let _ = env.throw_new(
                "java/lang/RuntimeException",
                format!("invalid environment JSON: {e}"),
            );
            return;
        }
    };

    if let Err(e) = apply_env_json(&payload) {
        let _ = env.throw_new("java/lang/RuntimeException", format!("setEnv error: {e}"));
    }
}

#[no_mangle]
pub extern "system" fn Java_com_godaddy_asherah_jni_AsherahNative_getSession(
    mut env: JNIEnv,
    _class: JClass,
    factory_handle: jlong,
    partition_id: JString,
) -> jlong {
    let Some(factory) = (unsafe { from_handle::<Factory>(factory_handle) }) else {
        let _ = env.throw_new("java/lang/RuntimeException", "factory handle is null");
        return 0;
    };

    let partition: String = match env.get_string(&partition_id) {
        Ok(s) => s.into(),
        Err(e) => {
            let _ = env.throw_new(
                "java/lang/RuntimeException",
                format!("invalid partition id: {e}"),
            );
            return 0;
        }
    };

    let session = factory.get_session(&partition);
    Box::into_raw(Box::new(session)) as jlong
}

#[no_mangle]
pub extern "system" fn Java_com_godaddy_asherah_jni_AsherahNative_closeSession(
    mut env: JNIEnv,
    _class: JClass,
    session_handle: jlong,
) {
    let Some(session) = (unsafe { from_handle::<Session>(session_handle) }) else {
        let _ = env.throw_new("java/lang/RuntimeException", "session handle is null");
        return;
    };
    if let Err(e) = session.close() {
        let _ = env.throw_new(
            "java/lang/RuntimeException",
            format!("session close error: {e}"),
        );
    }
}

#[no_mangle]
pub extern "system" fn Java_com_godaddy_asherah_jni_AsherahNative_freeSession(
    _env: JNIEnv,
    _class: JClass,
    session_handle: jlong,
) {
    if session_handle != 0 {
        unsafe { drop(Box::from_raw(session_handle as *mut Session)) }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_godaddy_asherah_jni_AsherahNative_encrypt(
    mut env: JNIEnv,
    _class: JClass,
    session_handle: jlong,
    plaintext: JByteArray,
) -> jbyteArray {
    let Some(session) = (unsafe { from_handle::<Session>(session_handle) }) else {
        let _ = env.throw_new("java/lang/RuntimeException", "session handle is null");
        return ptr::null_mut();
    };

    let data = match env.convert_byte_array(plaintext) {
        Ok(d) => d,
        Err(e) => {
            let _ = env.throw_new(
                "java/lang/RuntimeException",
                format!("failed to read plaintext: {e}"),
            );
            return ptr::null_mut();
        }
    };

    let result = session
        .encrypt(&data)
        .and_then(|drr| serde_json::to_vec(&drr).map_err(|e| anyhow::anyhow!(e)))
        .map_err(|e| {
            let _ = env.throw_new("java/lang/RuntimeException", format!("encrypt error: {e}"));
        });

    let ciphertext = match result {
        Ok(ct) => ct,
        Err(_) => return ptr::null_mut(),
    };

    match env.byte_array_from_slice(&ciphertext) {
        Ok(arr) => arr.into_raw(),
        Err(e) => {
            let _ = env.throw_new(
                "java/lang/RuntimeException",
                format!("failed to create byte array: {e}"),
            );
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_godaddy_asherah_jni_AsherahNative_decrypt(
    mut env: JNIEnv,
    _class: JClass,
    session_handle: jlong,
    ciphertext: JByteArray,
) -> jbyteArray {
    let Some(session) = (unsafe { from_handle::<Session>(session_handle) }) else {
        let _ = env.throw_new("java/lang/RuntimeException", "session handle is null");
        return ptr::null_mut();
    };

    let data = match env.convert_byte_array(ciphertext) {
        Ok(d) => d,
        Err(e) => {
            let _ = env.throw_new(
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
            let _ = env.throw_new("java/lang/RuntimeException", format!("{e}"));
            return ptr::null_mut();
        }
    };

    match env.byte_array_from_slice(&plaintext) {
        Ok(arr) => arr.into_raw(),
        Err(e) => {
            let _ = env.throw_new(
                "java/lang/RuntimeException",
                format!("failed to create byte array: {e}"),
            );
            ptr::null_mut()
        }
    }
}
