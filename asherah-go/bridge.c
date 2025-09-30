#include "bridge.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
typedef HMODULE asherah_lib_handle;
#define ASHERAH_LOAD_LIBRARY(path) LoadLibraryA(path)
#define ASHERAH_CLOSE_LIBRARY(handle) FreeLibrary(handle)
#define ASHERAH_LOAD_SYMBOL(handle, name) GetProcAddress(handle, name)
#else
#include <dlfcn.h>
typedef void* asherah_lib_handle;
#define ASHERAH_LOAD_LIBRARY(path) dlopen(path, RTLD_LAZY | RTLD_LOCAL)
#define ASHERAH_CLOSE_LIBRARY(handle) dlclose(handle)
#define ASHERAH_LOAD_SYMBOL(handle, name) dlsym(handle, name)
#endif

typedef struct {
    const char* symbol;
    void** target;
} asherah_symbol;

typedef void* (*factory_new_from_env_t)(void);
typedef int (*apply_config_json_t)(const char*);
typedef void* (*factory_new_with_config_t)(const char*);
typedef void (*factory_free_t)(void*);
typedef void* (*factory_get_session_t)(void*, const char*);
typedef void (*session_free_t)(void*);
typedef int (*encrypt_to_json_t)(void*, const unsigned char*, size_t, AsherahBuffer*);
typedef int (*decrypt_from_json_t)(void*, const unsigned char*, size_t, AsherahBuffer*);
typedef void (*buffer_free_t)(AsherahBuffer*);
typedef const char* (*last_error_message_t)(void);

static asherah_lib_handle library_handle = NULL;
static factory_new_from_env_t p_factory_new_from_env = NULL;
static apply_config_json_t p_apply_config_json = NULL;
static factory_new_with_config_t p_factory_new_with_config = NULL;
static factory_free_t p_factory_free = NULL;
static factory_get_session_t p_factory_get_session = NULL;
static session_free_t p_session_free = NULL;
static encrypt_to_json_t p_encrypt_to_json = NULL;
static decrypt_from_json_t p_decrypt_from_json = NULL;
static buffer_free_t p_buffer_free = NULL;
static last_error_message_t p_last_error_message = NULL;

static char load_error[512] = {0};

static void asherah_set_load_error(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vsnprintf(load_error, sizeof(load_error), fmt, args);
    va_end(args);
}

static void asherah_clear_load_error(void) {
    load_error[0] = '\0';
}

static int asherah_load_symbols(void) {
    asherah_symbol symbols[] = {
        {"asherah_factory_new_from_env", (void**)&p_factory_new_from_env},
        {"asherah_apply_config_json", (void**)&p_apply_config_json},
        {"asherah_factory_new_with_config", (void**)&p_factory_new_with_config},
        {"asherah_factory_free", (void**)&p_factory_free},
        {"asherah_factory_get_session", (void**)&p_factory_get_session},
        {"asherah_session_free", (void**)&p_session_free},
        {"asherah_encrypt_to_json", (void**)&p_encrypt_to_json},
        {"asherah_decrypt_from_json", (void**)&p_decrypt_from_json},
        {"asherah_buffer_free", (void**)&p_buffer_free},
        {"asherah_last_error_message", (void**)&p_last_error_message},
    };

    const size_t count = sizeof(symbols) / sizeof(symbols[0]);
    for (size_t i = 0; i < count; ++i) {
        void* sym = ASHERAH_LOAD_SYMBOL(library_handle, symbols[i].symbol);
        if (!sym) {
            asherah_set_load_error("asherah-go: missing symbol %s", symbols[i].symbol);
            return -1;
        }
        *(symbols[i].target) = sym;
    }
    return 0;
}

int asherah_go_load(const char* path) {
    if (library_handle != NULL) {
        return 0;
    }

    if (path == NULL || path[0] == '\0') {
        asherah_set_load_error("asherah-go: library path was empty");
        return -1;
    }

#ifdef _WIN32
    library_handle = ASHERAH_LOAD_LIBRARY(path);
    if (!library_handle) {
        asherah_set_load_error("asherah-go: LoadLibrary failed for %s", path);
        return -1;
    }
#else
    library_handle = ASHERAH_LOAD_LIBRARY(path);
    if (!library_handle) {
        const char* err = dlerror();
        asherah_set_load_error("asherah-go: dlopen failed for %s (%s)", path, err ? err : "unknown error");
        return -1;
    }
#endif

    if (asherah_load_symbols() != 0) {
        ASHERAH_CLOSE_LIBRARY(library_handle);
        library_handle = NULL;
        return -1;
    }

    asherah_clear_load_error();
    return 0;
}

void asherah_go_unload(void) {
    if (library_handle) {
        ASHERAH_CLOSE_LIBRARY(library_handle);
        library_handle = NULL;
    }
    p_factory_new_from_env = NULL;
    p_apply_config_json = NULL;
    p_factory_new_with_config = NULL;
    p_factory_free = NULL;
    p_factory_get_session = NULL;
    p_session_free = NULL;
    p_encrypt_to_json = NULL;
    p_decrypt_from_json = NULL;
    p_buffer_free = NULL;
    p_last_error_message = NULL;
}

static bool asherah_library_ready(void) {
    if (library_handle == NULL) {
        asherah_set_load_error("asherah-go: library not loaded");
        return false;
    }
    return true;
}

int asherah_go_factory_from_config(const char* config_json, uintptr_t* out_factory) {
    if (!asherah_library_ready() || !p_factory_new_with_config) {
        return -1;
    }
    if (!out_factory) {
        asherah_set_load_error("asherah-go: output factory pointer was null");
        return -1;
    }
    void* ptr = p_factory_new_with_config(config_json);
    if (!ptr) {
        return -1;
    }
    *out_factory = (uintptr_t)ptr;
    return 0;
}

int asherah_go_factory_from_env(uintptr_t* out_factory) {
    if (!asherah_library_ready() || !p_factory_new_from_env) {
        return -1;
    }
    if (!out_factory) {
        asherah_set_load_error("asherah-go: output factory pointer was null");
        return -1;
    }
    void* ptr = p_factory_new_from_env();
    if (!ptr) {
        return -1;
    }
    *out_factory = (uintptr_t)ptr;
    return 0;
}

void asherah_go_factory_free(uintptr_t factory) {
    if (!factory || !p_factory_free) {
        return;
    }
    p_factory_free((void*)factory);
}

int asherah_go_factory_get_session(uintptr_t factory, const char* partition_id, uintptr_t* out_session) {
    if (!asherah_library_ready() || !p_factory_get_session) {
        return -1;
    }
    if (!factory) {
        asherah_set_load_error("asherah-go: factory pointer was null");
        return -1;
    }
    if (!out_session) {
        asherah_set_load_error("asherah-go: output session pointer was null");
        return -1;
    }
    void* ptr = p_factory_get_session((void*)factory, partition_id);
    if (!ptr) {
        return -1;
    }
    *out_session = (uintptr_t)ptr;
    return 0;
}

void asherah_go_session_free(uintptr_t session) {
    if (!session || !p_session_free) {
        return;
    }
    p_session_free((void*)session);
}

int asherah_go_encrypt(uintptr_t session, const unsigned char* data, size_t len, AsherahBuffer* out_buf) {
    if (!asherah_library_ready() || !p_encrypt_to_json) {
        return -1;
    }
    if (!session) {
        asherah_set_load_error("asherah-go: session pointer was null");
        return -1;
    }
    if (!out_buf) {
        asherah_set_load_error("asherah-go: output buffer was null");
        return -1;
    }
    out_buf->data = NULL;
    out_buf->len = 0;
    return p_encrypt_to_json((void*)session, data, len, out_buf);
}

int asherah_go_decrypt(uintptr_t session, const unsigned char* json, size_t len, AsherahBuffer* out_buf) {
    if (!asherah_library_ready() || !p_decrypt_from_json) {
        return -1;
    }
    if (!session) {
        asherah_set_load_error("asherah-go: session pointer was null");
        return -1;
    }
    if (!out_buf) {
        asherah_set_load_error("asherah-go: output buffer was null");
        return -1;
    }
    out_buf->data = NULL;
    out_buf->len = 0;
    return p_decrypt_from_json((void*)session, json, len, out_buf);
}

void asherah_go_buffer_free(AsherahBuffer* buf) {
    if (!buf || !p_buffer_free) {
        return;
    }
    p_buffer_free(buf);
}

const char* asherah_go_last_error(void) {
    if (p_last_error_message) {
        const char* err = p_last_error_message();
        if (err && err[0] != '\0') {
            return err;
        }
    }
    if (load_error[0] != '\0') {
        return load_error;
    }
    return "asherah-go: unknown error";
}
