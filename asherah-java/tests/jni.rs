#![allow(unsafe_code)]
#![allow(clippy::print_stderr, clippy::ptr_as_ptr)]

use std::sync::Once;

use asherah_java::{
    Java_com_godaddy_asherah_jni_AsherahNative_closeFactory,
    Java_com_godaddy_asherah_jni_AsherahNative_closeSession,
    Java_com_godaddy_asherah_jni_AsherahNative_decrypt,
    Java_com_godaddy_asherah_jni_AsherahNative_encrypt,
    Java_com_godaddy_asherah_jni_AsherahNative_factoryFromEnv,
    Java_com_godaddy_asherah_jni_AsherahNative_freeFactory,
    Java_com_godaddy_asherah_jni_AsherahNative_freeSession,
    Java_com_godaddy_asherah_jni_AsherahNative_getSession,
};
use jni::errors::StartJvmError;
use jni::objects::{JByteArray, JClass};
use jni::AttachGuard;
use jni::{InitArgsBuilder, JNIEnv, JNIVersion, JavaVM};
use serial_test::serial;

static INIT: Once = Once::new();

fn prepare_env() {
    INIT.call_once(|| {
        std::env::set_var("SERVICE_NAME", "svc");
        std::env::set_var("PRODUCT_ID", "prod");
        std::env::set_var("KMS", "static");
        std::env::set_var("STATIC_MASTER_KEY_HEX", "22".repeat(32));
        std::env::remove_var("SQLITE_PATH");
        std::env::remove_var("CONNECTION_STRING");
    });
}

fn create_vm() -> Result<JavaVM, StartJvmError> {
    let args = InitArgsBuilder::new()
        .version(JNIVersion::V8)
        .build()
        .expect("init args");
    JavaVM::new(args)
}

fn env_from_guard<'env>(guard: &'env AttachGuard<'env>) -> JNIEnv<'env> {
    unsafe { JNIEnv::from_raw(guard.get_native_interface().cast()) }.expect("env from guard")
}

#[allow(non_snake_case)]
#[allow(unused_mut)]
#[test]
#[serial]
fn jni_encrypt_decrypt_roundtrip() {
    prepare_env();
    let Ok(jvm) = create_vm() else {
        eprintln!("skipping JNI roundtrip test: Java runtime not available");
        return;
    };
    let attach = match jvm.attach_current_thread() {
        Ok(guard) => guard,
        Err(e) => {
            eprintln!("skipping JNI roundtrip test: failed to attach thread: {e}");
            return;
        }
    };

    let mut env = env_from_guard(&attach);
    let factory_class: JClass<'_> = env
        .find_class("java/lang/Object")
        .expect("find Object class");
    let factory_handle =
        Java_com_godaddy_asherah_jni_AsherahNative_factoryFromEnv(env, factory_class);
    assert_ne!(factory_handle, 0, "factory pointer should be non-zero");

    let mut env = env_from_guard(&attach);
    let session_class: JClass<'_> = env
        .find_class("java/lang/Object")
        .expect("find Object class");
    let partition = env.new_string("test-partition").expect("partition");
    let session_handle = Java_com_godaddy_asherah_jni_AsherahNative_getSession(
        env,
        session_class,
        factory_handle,
        partition,
    );
    assert_ne!(session_handle, 0, "session pointer should be non-zero");

    let plaintext = b"hello-java-jni";
    let env = env_from_guard(&attach);
    let pt_array = env
        .byte_array_from_slice(plaintext)
        .expect("create plaintext array");

    let mut env = env_from_guard(&attach);
    let encrypt_class: JClass<'_> = env
        .find_class("java/lang/Object")
        .expect("find Object class");
    let ciphertext_ptr = Java_com_godaddy_asherah_jni_AsherahNative_encrypt(
        env,
        encrypt_class,
        session_handle,
        pt_array,
    );
    assert_ne!(ciphertext_ptr, std::ptr::null_mut());
    let env = env_from_guard(&attach);
    let ciphertext = env
        .convert_byte_array(unsafe { JByteArray::from_raw(ciphertext_ptr) })
        .expect("convert ciphertext");

    let mut env = env_from_guard(&attach);
    let ct_array = env
        .byte_array_from_slice(&ciphertext)
        .expect("ciphertext array");
    let mut env = env_from_guard(&attach);
    let decrypt_class: JClass<'_> = env
        .find_class("java/lang/Object")
        .expect("find Object class");
    let plaintext_ptr = Java_com_godaddy_asherah_jni_AsherahNative_decrypt(
        env,
        decrypt_class,
        session_handle,
        ct_array,
    );
    assert_ne!(plaintext_ptr, std::ptr::null_mut());
    let env = env_from_guard(&attach);
    let decrypted = env
        .convert_byte_array(unsafe { JByteArray::from_raw(plaintext_ptr) })
        .expect("convert plaintext");
    assert_eq!(decrypted, plaintext);

    let mut env = env_from_guard(&attach);
    let close_class: JClass<'_> = env
        .find_class("java/lang/Object")
        .expect("find Object class");
    Java_com_godaddy_asherah_jni_AsherahNative_closeSession(env, close_class, session_handle);

    let mut env = env_from_guard(&attach);
    let free_session_class: JClass<'_> = env
        .find_class("java/lang/Object")
        .expect("find Object class");
    Java_com_godaddy_asherah_jni_AsherahNative_freeSession(env, free_session_class, session_handle);

    let mut env = env_from_guard(&attach);
    let close_factory_class: JClass<'_> = env
        .find_class("java/lang/Object")
        .expect("find Object class");
    Java_com_godaddy_asherah_jni_AsherahNative_closeFactory(
        env,
        close_factory_class,
        factory_handle,
    );

    let mut env = env_from_guard(&attach);
    let free_factory_class: JClass<'_> = env
        .find_class("java/lang/Object")
        .expect("find Object class");
    Java_com_godaddy_asherah_jni_AsherahNative_freeFactory(env, free_factory_class, factory_handle);
}
