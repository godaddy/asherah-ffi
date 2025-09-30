#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    unsigned char* data;
    size_t len;
} AsherahBuffer;

int asherah_go_load(const char* path);
void asherah_go_unload(void);

int asherah_go_factory_from_config(const char* config_json, uintptr_t* out_factory);
int asherah_go_factory_from_env(uintptr_t* out_factory);
void asherah_go_factory_free(uintptr_t factory);

int asherah_go_factory_get_session(uintptr_t factory, const char* partition_id, uintptr_t* out_session);
void asherah_go_session_free(uintptr_t session);

int asherah_go_encrypt(uintptr_t session, const unsigned char* data, size_t len, AsherahBuffer* out_buf);
int asherah_go_decrypt(uintptr_t session, const unsigned char* json, size_t len, AsherahBuffer* out_buf);

void asherah_go_buffer_free(AsherahBuffer* buf);
const char* asherah_go_last_error(void);

#ifdef __cplusplus
}
#endif
