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
use jni::objects::JClass;
use jni::strings::JNIString;
use jni::{InitArgsBuilder, JNIVersion, JavaVM};
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

#[allow(clippy::unwrap_in_result)]
fn create_vm() -> Result<JavaVM, StartJvmError> {
    let args = InitArgsBuilder::new()
        .version(JNIVersion::V1_8)
        .build()
        .expect("init args");
    JavaVM::new(args)
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

    jvm.attach_current_thread(|env| -> jni::errors::Result<()> {
        let factory_class: JClass<'_> = env
            .find_class(JNIString::from("java/lang/Object"))
            .expect("find Object class");

        let mut factory_env = unsafe { jni::EnvUnowned::from_raw(env.get_raw()) };
        let factory_handle =
            Java_com_godaddy_asherah_jni_AsherahNative_factoryFromEnv(factory_env, factory_class);
        assert_ne!(factory_handle, 0, "factory pointer should be non-zero");

        let session_class: JClass<'_> = env
            .find_class(JNIString::from("java/lang/Object"))
            .expect("find Object class");
        let partition = env.new_string("test-partition").expect("partition");
        let mut session_env = unsafe { jni::EnvUnowned::from_raw(env.get_raw()) };
        let session_handle = Java_com_godaddy_asherah_jni_AsherahNative_getSession(
            session_env,
            session_class,
            factory_handle,
            partition,
        );
        assert_ne!(session_handle, 0, "session pointer should be non-zero");

        let plaintext = b"hello-java-jni";
        let pt_array = env
            .byte_array_from_slice(plaintext)
            .expect("create plaintext array");

        let encrypt_class: JClass<'_> = env
            .find_class(JNIString::from("java/lang/Object"))
            .expect("find Object class");
        let mut encrypt_env = unsafe { jni::EnvUnowned::from_raw(env.get_raw()) };
        let ciphertext_arr = Java_com_godaddy_asherah_jni_AsherahNative_encrypt(
            encrypt_env,
            encrypt_class,
            session_handle,
            pt_array,
        );
        assert!(!ciphertext_arr.is_null());
        let ciphertext = env
            .convert_byte_array(&ciphertext_arr)
            .expect("convert ciphertext");

        let ct_array = env
            .byte_array_from_slice(&ciphertext)
            .expect("ciphertext array");
        let decrypt_class: JClass<'_> = env
            .find_class(JNIString::from("java/lang/Object"))
            .expect("find Object class");
        let mut decrypt_env = unsafe { jni::EnvUnowned::from_raw(env.get_raw()) };
        let plaintext_arr = Java_com_godaddy_asherah_jni_AsherahNative_decrypt(
            decrypt_env,
            decrypt_class,
            session_handle,
            ct_array,
        );
        assert!(!plaintext_arr.is_null());
        let decrypted = env
            .convert_byte_array(&plaintext_arr)
            .expect("convert plaintext");
        assert_eq!(decrypted, plaintext);

        let close_class: JClass<'_> = env
            .find_class(JNIString::from("java/lang/Object"))
            .expect("find Object class");
        let mut close_env = unsafe { jni::EnvUnowned::from_raw(env.get_raw()) };
        Java_com_godaddy_asherah_jni_AsherahNative_closeSession(
            close_env,
            close_class,
            session_handle,
        );

        let free_session_class: JClass<'_> = env
            .find_class(JNIString::from("java/lang/Object"))
            .expect("find Object class");
        let mut free_session_env = unsafe { jni::EnvUnowned::from_raw(env.get_raw()) };
        Java_com_godaddy_asherah_jni_AsherahNative_freeSession(
            free_session_env,
            free_session_class,
            session_handle,
        );

        let close_factory_class: JClass<'_> = env
            .find_class(JNIString::from("java/lang/Object"))
            .expect("find Object class");
        let mut close_factory_env = unsafe { jni::EnvUnowned::from_raw(env.get_raw()) };
        Java_com_godaddy_asherah_jni_AsherahNative_closeFactory(
            close_factory_env,
            close_factory_class,
            factory_handle,
        );

        let free_factory_class: JClass<'_> = env
            .find_class(JNIString::from("java/lang/Object"))
            .expect("find Object class");
        let mut free_factory_env = unsafe { jni::EnvUnowned::from_raw(env.get_raw()) };
        Java_com_godaddy_asherah_jni_AsherahNative_freeFactory(
            free_factory_env,
            free_factory_class,
            factory_handle,
        );

        Ok(())
    })
    .expect("JNI test failed");
}
