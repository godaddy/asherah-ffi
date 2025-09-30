package asherah

/*
#include <stdlib.h>
#include "bridge.h"
*/
import "C"

import (
    "encoding/json"
    "errors"
    "fmt"
    "os"
    "runtime"
    "sync"
    "unsafe"
)

var (
    globalMu        sync.RWMutex
    globalFactory   uintptr
    sessionCache    map[string]*session
    sessionCaching  bool
)

type session struct {
    ptr uintptr
}

// Setup configures the native Asherah factory using the provided configuration.
func Setup(cfg Config) error {
    if err := ensureLoaded(); err != nil {
        return err
    }

    if cfg.ServiceName == "" {
        return errors.New("asherah-go: ServiceName is required")
    }
    if cfg.ProductID == "" {
        return errors.New("asherah-go: ProductID is required")
    }
    if cfg.Metastore == "" {
        return errors.New("asherah-go: Metastore is required")
    }

    payload, err := cfg.toJSON()
    if err != nil {
        return fmt.Errorf("asherah-go: failed to encode config: %w", err)
    }

    cJSON := C.CString(string(payload))
    defer C.free(unsafe.Pointer(cJSON))

    var factory C.uintptr_t
    if rc := C.asherah_go_factory_from_config(cJSON, &factory); rc != 0 {
        return fmt.Errorf("asherah-go: factory setup failed: %s", lastErrorMessage())
    }

    caching := true
    if cfg.EnableSessionCaching != nil {
        caching = *cfg.EnableSessionCaching
    }

    globalMu.Lock()
    defer globalMu.Unlock()

    if globalFactory != 0 {
        // Already configured, free newly created factory and return error.
        C.asherah_go_factory_free(factory)
        return errors.New("asherah-go: setup already completed; call Shutdown first")
    }

    globalFactory = uintptr(factory)
    sessionCaching = caching
    if sessionCaching {
        sessionCache = make(map[string]*session)
    } else {
        sessionCache = nil
    }

    return nil
}

// SetupFromEnv initialises the factory using environment variables.
func SetupFromEnv() error {
    if err := ensureLoaded(); err != nil {
        return err
    }

    var factory C.uintptr_t
    if rc := C.asherah_go_factory_from_env(&factory); rc != 0 {
        return fmt.Errorf("asherah-go: factory_from_env failed: %s", lastErrorMessage())
    }

    globalMu.Lock()
    defer globalMu.Unlock()

    if globalFactory != 0 {
        C.asherah_go_factory_free(factory)
        return errors.New("asherah-go: setup already completed; call Shutdown first")
    }

    globalFactory = uintptr(factory)
    sessionCaching = true
    sessionCache = make(map[string]*session)
    return nil
}

// Shutdown releases the native factory and any cached sessions.
func Shutdown() {
    globalMu.Lock()
    factory := globalFactory
    cached := sessionCache
    globalFactory = 0
    sessionCache = nil
    sessionCaching = false
    globalMu.Unlock()

    for _, sess := range cached {
        C.asherah_go_session_free(C.uintptr_t(sess.ptr))
    }

    if factory != 0 {
        C.asherah_go_factory_free(C.uintptr_t(factory))
    }
}

// GetSetupStatus reports whether Setup has been called successfully.
func GetSetupStatus() bool {
    globalMu.RLock()
    defer globalMu.RUnlock()
    return globalFactory != 0
}

// Encrypt encrypts the provided plaintext and returns the DataRowRecord JSON payload.
func Encrypt(partition string, plaintext []byte) ([]byte, error) {
    sess, release, err := acquireSession(partition)
    if err != nil {
        return nil, err
    }
    if release != nil {
        defer release()
    }

    var buf C.AsherahBuffer
    var dataPtr *C.uchar
    if len(plaintext) > 0 {
        dataPtr = (*C.uchar)(unsafe.Pointer(&plaintext[0]))
    }
    rc := C.asherah_go_encrypt(C.uintptr_t(sess.ptr), dataPtr, C.size_t(len(plaintext)), &buf)
    runtimeKeepAliveBytes(plaintext)
    if rc != 0 {
        return nil, fmt.Errorf("asherah-go: encrypt failed: %s", lastErrorMessage())
    }
    defer C.asherah_go_buffer_free(&buf)
    return C.GoBytes(unsafe.Pointer(buf.data), C.int(buf.len)), nil
}

// EncryptString encrypts a UTF-8 string and returns a JSON string.
func EncryptString(partition string, plaintext string) (string, error) {
    data, err := Encrypt(partition, []byte(plaintext))
    if err != nil {
        return "", err
    }
    return string(data), nil
}

// Decrypt decrypts the provided DataRowRecord JSON payload.
func Decrypt(partition string, dataRowRecord []byte) ([]byte, error) {
    sess, release, err := acquireSession(partition)
    if err != nil {
        return nil, err
    }
    if release != nil {
        defer release()
    }

    var buf C.AsherahBuffer
    var jsonPtr *C.uchar
    if len(dataRowRecord) > 0 {
        jsonPtr = (*C.uchar)(unsafe.Pointer(&dataRowRecord[0]))
    }
    rc := C.asherah_go_decrypt(C.uintptr_t(sess.ptr), jsonPtr, C.size_t(len(dataRowRecord)), &buf)
    runtimeKeepAliveBytes(dataRowRecord)
    if rc != 0 {
        return nil, fmt.Errorf("asherah-go: decrypt failed: %s", lastErrorMessage())
    }
    defer C.asherah_go_buffer_free(&buf)
    return C.GoBytes(unsafe.Pointer(buf.data), C.int(buf.len)), nil
}

// DecryptString decrypts the provided DataRowRecord JSON payload and returns a UTF-8 string.
func DecryptString(partition string, dataRowRecord string) (string, error) {
    data, err := Decrypt(partition, []byte(dataRowRecord))
    if err != nil {
        return "", err
    }
    return string(data), nil
}

// SetEnvJSON applies environment variables from a JSON object payload, matching the behaviour of other bindings.
func SetEnvJSON(payload []byte) error {
    var values map[string]*string
    if err := json.Unmarshal(payload, &values); err != nil {
        return fmt.Errorf("asherah-go: invalid environment JSON: %w", err)
    }
    SetEnvMap(values)
    return nil
}

// SetEnvMap applies environment variables from a map of key to optional value.
func SetEnvMap(values map[string]*string) {
    for key, value := range values {
        if value == nil {
            _ = os.Unsetenv(key)
        } else {
            _ = os.Setenv(key, *value)
        }
    }
}

func acquireSession(partition string) (*session, func(), error) {
    if partition == "" {
        return nil, nil, errors.New("asherah-go: partition ID cannot be empty")
    }

    globalMu.RLock()
    factory := globalFactory
    caching := sessionCaching
    globalMu.RUnlock()

    if factory == 0 {
        return nil, nil, errors.New("asherah-go: Setup must be called before use")
    }

    if caching {
        globalMu.Lock()
        if sess, ok := sessionCache[partition]; ok {
            globalMu.Unlock()
            return sess, nil, nil
        }
        globalMu.Unlock()
    }

    cPartition := C.CString(partition)
    defer C.free(unsafe.Pointer(cPartition))

    var sessionPtr C.uintptr_t
    if rc := C.asherah_go_factory_get_session(C.uintptr_t(factory), cPartition, &sessionPtr); rc != 0 {
        return nil, nil, fmt.Errorf("asherah-go: get_session failed: %s", lastErrorMessage())
    }

    sess := &session{ptr: uintptr(sessionPtr)}

    if caching {
        globalMu.Lock()
        if existing, ok := sessionCache[partition]; ok {
            globalMu.Unlock()
            C.asherah_go_session_free(sessionPtr)
            return existing, nil, nil
        }
        if sessionCache == nil {
            sessionCache = make(map[string]*session)
        }
        sessionCache[partition] = sess
        globalMu.Unlock()
        return sess, nil, nil
    }

    release := func() {
        C.asherah_go_session_free(sessionPtr)
    }
    return sess, release, nil
}

func runtimeKeepAliveBytes(b []byte) {
    if len(b) == 0 {
        return
    }
    runtime.KeepAlive(b)
}
