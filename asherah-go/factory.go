package asherah

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"
)

// Factory creates cryptographic sessions for encrypt/decrypt operations.
// It must be closed when no longer needed.
type Factory struct {
	mu  sync.Mutex
	ptr uintptr
}

// NewFactory creates a Factory from the provided configuration.
func NewFactory(cfg Config) (*Factory, error) {
	if err := ensureLoaded(); err != nil {
		return nil, err
	}

	if cfg.ServiceName == "" {
		return nil, errors.New("asherah-go: ServiceName is required")
	}
	if cfg.ProductID == "" {
		return nil, errors.New("asherah-go: ProductID is required")
	}
	if cfg.Metastore == "" {
		return nil, errors.New("asherah-go: Metastore is required")
	}

	payload, err := cfg.toJSON()
	if err != nil {
		return nil, fmt.Errorf("asherah-go: failed to encode config: %w", err)
	}

	ptr := fnFactoryNewWithConfig(string(payload))
	if ptr == 0 {
		return nil, fmt.Errorf("asherah-go: factory creation failed: %s", lastErrorMessage())
	}

	return &Factory{ptr: ptr}, nil
}

// NewFactoryFromEnv creates a Factory using environment variables.
func NewFactoryFromEnv() (*Factory, error) {
	if err := ensureLoaded(); err != nil {
		return nil, err
	}

	ptr := fnFactoryNewFromEnv()
	if ptr == 0 {
		return nil, fmt.Errorf("asherah-go: factory_from_env failed: %s", lastErrorMessage())
	}

	return &Factory{ptr: ptr}, nil
}

// GetSession creates a Session for the given partition ID.
func (f *Factory) GetSession(partitionID string) (*Session, error) {
	if partitionID == "" {
		return nil, errors.New("asherah-go: partition ID cannot be empty")
	}
	f.mu.Lock()
	p := f.ptr
	f.mu.Unlock()
	if p == 0 {
		return nil, errors.New("asherah-go: factory is closed")
	}

	ptr := fnFactoryGetSession(p, partitionID)
	if ptr == 0 {
		return nil, fmt.Errorf("asherah-go: get_session failed: %s", lastErrorMessage())
	}

	return &Session{ptr: ptr}, nil
}

// Close releases the native factory. Any sessions obtained from this
// factory should be closed before calling this method.
func (f *Factory) Close() {
	f.mu.Lock()
	p := f.ptr
	f.ptr = 0
	f.mu.Unlock()
	if p != 0 {
		fnFactoryFree(p)
	}
}

// Session provides encrypt/decrypt operations for a specific partition.
// It must be closed when no longer needed (unless managed by the global API).
type Session struct {
	mu  sync.Mutex
	ptr uintptr
}

// Encrypt encrypts the provided plaintext and returns the DataRowRecord JSON.
func (s *Session) Encrypt(plaintext []byte) ([]byte, error) {
	s.mu.Lock()
	p := s.ptr
	s.mu.Unlock()
	if p == 0 {
		return nil, errors.New("asherah-go: session is closed")
	}

	var buf asherahBuffer
	var dataPtr uintptr
	if len(plaintext) > 0 {
		dataPtr = uintptr(unsafe.Pointer(&plaintext[0]))
	}
	rc := fnEncryptToJSON(p, dataPtr, uintptr(len(plaintext)), uintptr(unsafe.Pointer(&buf)))
	runtime.KeepAlive(plaintext)
	if rc != 0 {
		return nil, fmt.Errorf("asherah-go: encrypt failed: %s", lastErrorMessage())
	}
	defer freeBuffer(&buf)
	return readBuffer(&buf), nil
}

// EncryptString encrypts a UTF-8 string and returns a JSON string.
func (s *Session) EncryptString(plaintext string) (string, error) {
	data, err := s.Encrypt([]byte(plaintext))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// Decrypt decrypts the provided DataRowRecord JSON.
func (s *Session) Decrypt(dataRowRecord []byte) ([]byte, error) {
	s.mu.Lock()
	p := s.ptr
	s.mu.Unlock()
	if p == 0 {
		return nil, errors.New("asherah-go: session is closed")
	}

	var buf asherahBuffer
	var jsonPtr uintptr
	if len(dataRowRecord) > 0 {
		jsonPtr = uintptr(unsafe.Pointer(&dataRowRecord[0]))
	}
	rc := fnDecryptFromJSON(p, jsonPtr, uintptr(len(dataRowRecord)), uintptr(unsafe.Pointer(&buf)))
	runtime.KeepAlive(dataRowRecord)
	if rc != 0 {
		return nil, fmt.Errorf("asherah-go: decrypt failed: %s", lastErrorMessage())
	}
	defer freeBuffer(&buf)
	return readBuffer(&buf), nil
}

// DecryptString decrypts the provided DataRowRecord JSON and returns a UTF-8 string.
func (s *Session) DecryptString(dataRowRecord string) (string, error) {
	data, err := s.Decrypt([]byte(dataRowRecord))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// Close releases the native session.
func (s *Session) Close() {
	s.mu.Lock()
	p := s.ptr
	s.ptr = 0
	s.mu.Unlock()
	if p != 0 {
		fnSessionFree(p)
	}
}
