#![allow(unsafe_code)]

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use libloading::Library;
use once_cell::sync::Lazy;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::ffi::{c_char, c_int, c_void, CString};
use std::ptr;

#[repr(C)]
struct AsherahBuffer {
    data: *mut u8,
    len: usize,
}

type RustFactoryNewFn = unsafe extern "C" fn() -> *mut c_void;
type RustFactoryGetSessionFn = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;
type RustFactoryFreeFn = unsafe extern "C" fn(*mut c_void);
type RustSessionFreeFn = unsafe extern "C" fn(*mut c_void);
type RustCryptFn = unsafe extern "C" fn(*mut c_void, *const u8, usize, *mut AsherahBuffer) -> c_int;
type RustBufferFreeFn = unsafe extern "C" fn(*mut AsherahBuffer);

type GoFactoryNewFn = unsafe extern "C" fn() -> usize;
type GoFactoryFreeFn = unsafe extern "C" fn(usize);
type GoFactoryGetSessionFn = unsafe extern "C" fn(usize, *const c_char) -> usize;
type GoSessionFreeFn = unsafe extern "C" fn(usize);
type GoCryptFn = unsafe extern "C" fn(usize, *const u8, usize, *mut AsherahBuffer) -> c_int;
type GoBufferFreeFn = unsafe extern "C" fn(*mut AsherahBuffer);

struct RustApi {
    _lib: &'static Library,
    factory_new: RustFactoryNewFn,
    factory_get_session: RustFactoryGetSessionFn,
    factory_free: RustFactoryFreeFn,
    session_free: RustSessionFreeFn,
    encrypt: RustCryptFn,
    decrypt: RustCryptFn,
    buffer_free: RustBufferFreeFn,
}

struct GoApi {
    _lib: &'static Library,
    factory_new: GoFactoryNewFn,
    factory_free: GoFactoryFreeFn,
    factory_get_session: GoFactoryGetSessionFn,
    session_free: GoSessionFreeFn,
    encrypt: GoCryptFn,
    decrypt: GoCryptFn,
    buffer_free: GoBufferFreeFn,
}

struct Libraries {
    rust: RustApi,
    go: GoApi,
}

impl Libraries {
    fn load() -> anyhow::Result<Self> {
        let rust_lib_path = env!("RUST_FFI_LIB_PATH");
        let go_lib_path = env!("GO_FFI_LIB_PATH");

        unsafe {
            let rust_library = Box::leak(Box::new(Library::new(rust_lib_path)?));
            let go_library = Box::leak(Box::new(Library::new(go_lib_path)?));

            let rust = RustApi {
                _lib: rust_library,
                factory_new: *rust_library
                    .get::<RustFactoryNewFn>(b"asherah_factory_new_from_env")?
                    .into_raw(),
                factory_get_session: *rust_library
                    .get::<RustFactoryGetSessionFn>(b"asherah_factory_get_session")?
                    .into_raw(),
                factory_free: *rust_library
                    .get::<RustFactoryFreeFn>(b"asherah_factory_free")?
                    .into_raw(),
                session_free: *rust_library
                    .get::<RustSessionFreeFn>(b"asherah_session_free")?
                    .into_raw(),
                encrypt: *rust_library
                    .get::<RustCryptFn>(b"asherah_encrypt_to_json")?
                    .into_raw(),
                decrypt: *rust_library
                    .get::<RustCryptFn>(b"asherah_decrypt_from_json")?
                    .into_raw(),
                buffer_free: *rust_library
                    .get::<RustBufferFreeFn>(b"asherah_buffer_free")?
                    .into_raw(),
            };

            let go = GoApi {
                _lib: go_library,
                factory_new: *go_library
                    .get::<GoFactoryNewFn>(b"asherah_go_factory_new_from_env")?
                    .into_raw(),
                factory_free: *go_library
                    .get::<GoFactoryFreeFn>(b"asherah_go_factory_free")?
                    .into_raw(),
                factory_get_session: *go_library
                    .get::<GoFactoryGetSessionFn>(b"asherah_go_factory_get_session")?
                    .into_raw(),
                session_free: *go_library
                    .get::<GoSessionFreeFn>(b"asherah_go_session_free")?
                    .into_raw(),
                encrypt: *go_library
                    .get::<GoCryptFn>(b"asherah_go_encrypt_to_json")?
                    .into_raw(),
                decrypt: *go_library
                    .get::<GoCryptFn>(b"asherah_go_decrypt_from_json")?
                    .into_raw(),
                buffer_free: *go_library
                    .get::<GoBufferFreeFn>(b"asherah_go_buffer_free")?
                    .into_raw(),
            };

            Ok(Self { rust, go })
        }
    }
}

static LIBRARIES: Lazy<Libraries> = Lazy::new(|| Libraries::load().expect("load libraries"));

struct RustContext {
    api: &'static RustApi,
    factory: *mut c_void,
    session: *mut c_void,
}

struct GoContext {
    api: &'static GoApi,
    factory: usize,
    session: usize,
}

impl RustContext {
    fn new(api: &'static RustApi, partition: &CStrHelper) -> Self {
        unsafe {
            let factory = (api.factory_new)();
            assert!(!factory.is_null(), "failed to create Rust factory");
            let session = (api.factory_get_session)(factory, partition.as_ptr());
            assert!(!session.is_null(), "failed to create Rust session");
            Self {
                api,
                factory,
                session,
            }
        }
    }

    fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        unsafe {
            let mut buffer = AsherahBuffer {
                data: ptr::null_mut(),
                len: 0,
            };
            let result = (self.api.encrypt)(self.session, data.as_ptr(), data.len(), &mut buffer);
            assert_eq!(result, 0, "Rust encrypt returned error");
            let slice = std::slice::from_raw_parts(buffer.data, buffer.len);
            let vec = slice.to_vec();
            (self.api.buffer_free)(&mut buffer);
            vec
        }
    }

    fn decrypt(&self, ciphertext: &[u8]) {
        unsafe {
            let mut buffer = AsherahBuffer {
                data: ptr::null_mut(),
                len: 0,
            };
            let result = (self.api.decrypt)(
                self.session,
                ciphertext.as_ptr(),
                ciphertext.len(),
                &mut buffer,
            );
            assert_eq!(result, 0, "Rust decrypt returned error");
            if buffer.len > 0 {
                (self.api.buffer_free)(&mut buffer);
            }
        }
    }
}

impl Drop for RustContext {
    fn drop(&mut self) {
        unsafe {
            (self.api.session_free)(self.session);
            (self.api.factory_free)(self.factory);
        }
    }
}

impl GoContext {
    fn new(api: &'static GoApi, partition: &CStrHelper) -> Self {
        unsafe {
            let factory = (api.factory_new)();
            assert!(factory != 0, "failed to create Go factory");
            let session = (api.factory_get_session)(factory, partition.as_ptr());
            assert!(session != 0, "failed to create Go session");
            Self {
                api,
                factory,
                session,
            }
        }
    }

    fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        unsafe {
            let mut buffer = AsherahBuffer {
                data: ptr::null_mut(),
                len: 0,
            };
            let result = (self.api.encrypt)(self.session, data.as_ptr(), data.len(), &mut buffer);
            assert_eq!(result, 0, "Go encrypt returned error");
            let slice = std::slice::from_raw_parts(buffer.data, buffer.len);
            let vec = slice.to_vec();
            (self.api.buffer_free)(&mut buffer);
            vec
        }
    }

    fn decrypt(&self, ciphertext: &[u8]) {
        unsafe {
            let mut buffer = AsherahBuffer {
                data: ptr::null_mut(),
                len: 0,
            };
            let result = (self.api.decrypt)(
                self.session,
                ciphertext.as_ptr(),
                ciphertext.len(),
                &mut buffer,
            );
            assert_eq!(result, 0, "Go decrypt returned error");
            if buffer.len > 0 {
                (self.api.buffer_free)(&mut buffer);
            }
        }
    }
}

impl Drop for GoContext {
    fn drop(&mut self) {
        unsafe {
            (self.api.session_free)(self.session);
            (self.api.factory_free)(self.factory);
        }
    }
}

struct CStrHelper {
    inner: CString,
}

impl CStrHelper {
    fn new(s: &str) -> Self {
        Self {
            inner: CString::new(s).expect("cstring"),
        }
    }

    fn as_ptr(&self) -> *const c_char {
        self.inner.as_ptr()
    }
}

fn prepare_contexts() -> (RustContext, GoContext) {
    std::env::set_var("SERVICE_NAME", "bench_service");
    std::env::set_var("PRODUCT_ID", "bench_product");
    std::env::set_var("STATIC_MASTER_KEY_HEX", "22".repeat(32));

    let partition = CStrHelper::new("partition-1");
    let rust_ctx = RustContext::new(&LIBRARIES.rust, &partition);
    let go_ctx = GoContext::new(&LIBRARIES.go, &partition);
    (rust_ctx, go_ctx)
}

fn bench_encrypt(c: &mut Criterion) {
    let (rust_ctx, go_ctx) = prepare_contexts();
    let mut rng = StdRng::seed_from_u64(12345);
    let mut data = vec![0u8; 4096];
    rng.fill_bytes(&mut data);

    let mut group = c.benchmark_group("encrypt");
    group.bench_function(BenchmarkId::new("rust", data.len()), |b| {
        b.iter(|| {
            let ciphertext = rust_ctx.encrypt(&data);
            drop(ciphertext);
        })
    });
    group.bench_function(BenchmarkId::new("go", data.len()), |b| {
        b.iter(|| {
            let ciphertext = go_ctx.encrypt(&data);
            drop(ciphertext);
        })
    });
    group.finish();

    // Leak contexts to keep factories alive for decrypt bench preparation
    std::mem::forget(rust_ctx);
    std::mem::forget(go_ctx);
}

fn bench_decrypt(c: &mut Criterion) {
    let (rust_ctx, go_ctx) = prepare_contexts();
    let mut rng = StdRng::seed_from_u64(67890);
    let mut data = vec![0u8; 4096];
    rng.fill_bytes(&mut data);

    let rust_cipher = rust_ctx.encrypt(&data);
    let go_cipher = go_ctx.encrypt(&data);

    let mut group = c.benchmark_group("decrypt");
    group.bench_function(BenchmarkId::new("rust", rust_cipher.len()), |b| {
        b.iter(|| {
            rust_ctx.decrypt(&rust_cipher);
        })
    });
    group.bench_function(BenchmarkId::new("go", go_cipher.len()), |b| {
        b.iter(|| {
            go_ctx.decrypt(&go_cipher);
        })
    });
    group.finish();
}

criterion_group!(benches, bench_encrypt, bench_decrypt);
criterion_main!(benches);
