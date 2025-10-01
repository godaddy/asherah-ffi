package main

/*
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint8_t* data;
    size_t len;
} AsherahBuffer;
*/
import "C"

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"unsafe"

	appencryption "github.com/godaddy/asherah/go/appencryption"
	"github.com/godaddy/asherah/go/appencryption/pkg/crypto/aead"
	"github.com/godaddy/asherah/go/appencryption/pkg/kms"
	"github.com/godaddy/asherah/go/appencryption/pkg/persistence"
)

type handleStore[T any] struct {
	mu     sync.Mutex
	next   uintptr
	values map[uintptr]T
}

func newHandleStore[T any]() *handleStore[T] {
	return &handleStore[T]{
		next:   1,
		values: make(map[uintptr]T),
	}
}

func (s *handleStore[T]) add(value T) uintptr {
	s.mu.Lock()
	defer s.mu.Unlock()
	handle := s.next
	s.next++
	s.values[handle] = value
	return handle
}

func (s *handleStore[T]) get(handle uintptr) (T, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.values[handle]
	return value, ok
}

func (s *handleStore[T]) remove(handle uintptr) (T, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.values[handle]
	if ok {
		delete(s.values, handle)
	}
	return value, ok
}

var (
	factoryHandles = newHandleStore[*appencryption.SessionFactory]()
	sessionHandles = newHandleStore[*appencryption.Session]()

	errMu   sync.Mutex
	lastErr string
)

func setError(err error) {
	errMu.Lock()
	defer errMu.Unlock()
	if err != nil {
		lastErr = err.Error()
	} else {
		lastErr = ""
	}
}

func getErrorCString() *C.char {
	errMu.Lock()
	defer errMu.Unlock()
	if lastErr == "" {
		return nil
	}
	return C.CString(lastErr)
}

func ensureStaticKey(key string) (string, error) {
	trimmed := strings.TrimSpace(key)
	if trimmed == "" {
		return "", errors.New("STATIC_MASTER_KEY_HEX must be set")
	}
	if len(trimmed)%2 != 0 {
		return "", errors.New("STATIC_MASTER_KEY_HEX must be even length hex")
	}
	if _, err := hex.DecodeString(trimmed); err != nil {
		return "", fmt.Errorf("invalid STATIC_MASTER_KEY_HEX: %w", err)
	}
	return trimmed, nil
}

func buildFactory() (*appencryption.SessionFactory, error) {
	svc := os.Getenv("SERVICE_NAME")
	if svc == "" {
		svc = "svc"
	}
	product := os.Getenv("PRODUCT_ID")
	if product == "" {
		product = "prod"
	}

	staticHex, err := ensureStaticKey(os.Getenv("STATIC_MASTER_KEY_HEX"))
	if err != nil {
		return nil, err
	}

	crypto := aead.NewAES256GCM()
	metastore := persistence.NewMemoryMetastore()
	kmsService, err := kms.NewStatic(staticHex, crypto)
	if err != nil {
		return nil, err
	}

	cfg := &appencryption.Config{
		Service: svc,
		Product: product,
		Policy:  appencryption.NewCryptoPolicy(),
	}

	factory := appencryption.NewSessionFactory(cfg, metastore, kmsService, crypto, appencryption.WithMetrics(false))
	return factory, nil
}

func fillBuffer(out *C.AsherahBuffer, data []byte) C.int {
	if out == nil {
		setError(errors.New("nil output buffer"))
		return -1
	}
	if len(data) == 0 {
		out.data = nil
		out.len = 0
		return 0
	}

	ptr := C.malloc(C.size_t(len(data)))
	if ptr == nil {
		setError(errors.New("malloc failed"))
		return -1
	}
	if len(data) > 0 {
		C.memcpy(ptr, unsafe.Pointer(&data[0]), C.size_t(len(data)))
	}
	out.data = (*C.uint8_t)(ptr)
	out.len = C.size_t(len(data))
	return 0
}

//export asherah_go_last_error_message
func asherah_go_last_error_message() *C.char {
	return getErrorCString()
}

//export asherah_go_free_cstring
func asherah_go_free_cstring(str *C.char) {
	if str != nil {
		C.free(unsafe.Pointer(str))
	}
}

//export asherah_go_factory_new_from_env
func asherah_go_factory_new_from_env() C.uintptr_t {
	factory, err := buildFactory()
	if err != nil {
		setError(err)
		return 0
	}
	handle := factoryHandles.add(factory)
	return C.uintptr_t(handle)
}

//export asherah_go_factory_free
func asherah_go_factory_free(handle C.uintptr_t) {
	if handle == 0 {
		return
	}
	if factory, ok := factoryHandles.remove(uintptr(handle)); ok {
		_ = factory.Close()
	}
}

func convertCString(str *C.char) (string, error) {
	if str == nil {
		return "", errors.New("nil string")
	}
	return C.GoString(str), nil
}

//export asherah_go_factory_get_session
func asherah_go_factory_get_session(handle C.uintptr_t, partition *C.char) C.uintptr_t {
	factory, ok := factoryHandles.get(uintptr(handle))
	if !ok {
		setError(errors.New("invalid factory handle"))
		return 0
	}

	pid, err := convertCString(partition)
	if err != nil {
		setError(err)
		return 0
	}

	session, err := factory.GetSession(pid)
	if err != nil {
		setError(err)
		return 0
	}
	handleID := sessionHandles.add(session)
	return C.uintptr_t(handleID)
}

//export asherah_go_session_free
func asherah_go_session_free(handle C.uintptr_t) {
	if handle == 0 {
		return
	}
	if session, ok := sessionHandles.remove(uintptr(handle)); ok {
		_ = session.Close()
	}
}

//export asherah_go_encrypt_to_json
func asherah_go_encrypt_to_json(sessionHandle C.uintptr_t, data *C.uint8_t, length C.size_t, out *C.AsherahBuffer) C.int {
	session, ok := sessionHandles.get(uintptr(sessionHandle))
	if !ok {
		setError(errors.New("invalid session handle"))
		return -1
	}
	if data == nil && length > 0 {
		setError(errors.New("nil data"))
		return -1
	}

	payload := unsafe.Slice((*byte)(unsafe.Pointer(data)), int(length))
	drr, err := session.Encrypt(context.Background(), payload)
	if err != nil {
		setError(err)
		return -1
	}

	bytes, err := json.Marshal(drr)
	if err != nil {
		setError(err)
		return -1
	}

	return fillBuffer(out, bytes)
}

//export asherah_go_decrypt_from_json
func asherah_go_decrypt_from_json(sessionHandle C.uintptr_t, jsonBytes *C.uint8_t, length C.size_t, out *C.AsherahBuffer) C.int {
	session, ok := sessionHandles.get(uintptr(sessionHandle))
	if !ok {
		setError(errors.New("invalid session handle"))
		return -1
	}
	if jsonBytes == nil && length > 0 {
		setError(errors.New("nil json"))
		return -1
	}

	raw := unsafe.Slice((*byte)(unsafe.Pointer(jsonBytes)), int(length))
	var drr appencryption.DataRowRecord
	if err := json.Unmarshal(raw, &drr); err != nil {
		setError(err)
		return -1
	}

	plaintext, err := session.Decrypt(context.Background(), drr)
	if err != nil {
		setError(err)
		return -1
	}

	return fillBuffer(out, plaintext)
}

//export asherah_go_buffer_free
func asherah_go_buffer_free(buf *C.AsherahBuffer) {
	if buf == nil {
		return
	}
	if buf.data != nil && buf.len > 0 {
		C.free(unsafe.Pointer(buf.data))
	}
	buf.data = nil
	buf.len = 0
}

func main() {}
