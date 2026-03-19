package asherah

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
)

// Global (module-level) API — convenience wrappers around Factory/Session.

const defaultSessionCacheMaxSize = 1000

var (
	globalMu             sync.RWMutex
	globalFactory        *Factory
	sessionCache         map[string]*Session
	sessionCacheOrder    []string // insertion order for LRU eviction
	sessionCacheMaxSize  int
	sessionCaching       bool
)

// Setup configures the global Asherah factory using the provided configuration.
func Setup(cfg Config) error {
	factory, err := NewFactory(cfg)
	if err != nil {
		return err
	}

	caching := true
	if cfg.EnableSessionCaching != nil {
		caching = *cfg.EnableSessionCaching
	}

	globalMu.Lock()
	defer globalMu.Unlock()

	if globalFactory != nil {
		factory.Close()
		return errors.New("asherah-go: setup already completed; call Shutdown first")
	}

	globalFactory = factory
	sessionCaching = caching
	sessionCacheMaxSize = defaultSessionCacheMaxSize
	if cfg.SessionCacheMaxSize != nil && *cfg.SessionCacheMaxSize > 0 {
		sessionCacheMaxSize = *cfg.SessionCacheMaxSize
	}
	if sessionCaching {
		sessionCache = make(map[string]*Session)
		sessionCacheOrder = nil
	} else {
		sessionCache = nil
		sessionCacheOrder = nil
	}

	return nil
}

// SetupFromEnv initialises the global factory using environment variables.
func SetupFromEnv() error {
	factory, err := NewFactoryFromEnv()
	if err != nil {
		return err
	}

	globalMu.Lock()
	defer globalMu.Unlock()

	if globalFactory != nil {
		factory.Close()
		return errors.New("asherah-go: setup already completed; call Shutdown first")
	}

	globalFactory = factory
	sessionCaching = true
	sessionCache = make(map[string]*Session)
	return nil
}

// Shutdown releases the global factory and any cached sessions.
func Shutdown() {
	globalMu.Lock()
	factory := globalFactory
	cached := sessionCache
	globalFactory = nil
	sessionCache = nil
	sessionCaching = false
	globalMu.Unlock()

	for _, sess := range cached {
		sess.Close()
	}

	if factory != nil {
		factory.Close()
	}
}

// GetSetupStatus reports whether Setup has been called successfully.
func GetSetupStatus() bool {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalFactory != nil
}

// Encrypt encrypts the provided plaintext using the global factory.
func Encrypt(partition string, plaintext []byte) ([]byte, error) {
	sess, release, err := acquireSession(partition)
	if err != nil {
		return nil, err
	}
	if release != nil {
		defer release()
	}
	return sess.Encrypt(plaintext)
}

// EncryptString encrypts a UTF-8 string and returns a JSON string.
func EncryptString(partition string, plaintext string) (string, error) {
	data, err := Encrypt(partition, []byte(plaintext))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// Decrypt decrypts the provided DataRowRecord JSON payload using the global factory.
func Decrypt(partition string, dataRowRecord []byte) ([]byte, error) {
	sess, release, err := acquireSession(partition)
	if err != nil {
		return nil, err
	}
	if release != nil {
		defer release()
	}
	return sess.Decrypt(dataRowRecord)
}

// DecryptString decrypts the provided DataRowRecord JSON payload and returns a UTF-8 string.
func DecryptString(partition string, dataRowRecord string) (string, error) {
	data, err := Decrypt(partition, []byte(dataRowRecord))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// SetEnvJSON applies environment variables from a JSON object payload.
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

func acquireSession(partition string) (*Session, func(), error) {
	if partition == "" {
		return nil, nil, errors.New("asherah-go: partition ID cannot be empty")
	}

	globalMu.RLock()
	factory := globalFactory
	caching := sessionCaching
	globalMu.RUnlock()

	if factory == nil {
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

	sess, err := factory.GetSession(partition)
	if err != nil {
		return nil, nil, err
	}

	if caching {
		globalMu.Lock()
		if existing, ok := sessionCache[partition]; ok {
			globalMu.Unlock()
			sess.Close()
			return existing, nil, nil
		}
		if sessionCache == nil {
			sessionCache = make(map[string]*Session)
		}
		sessionCache[partition] = sess
		sessionCacheOrder = append(sessionCacheOrder, partition)
		// Evict oldest entries if cache exceeds max size
		for len(sessionCache) > sessionCacheMaxSize && len(sessionCacheOrder) > 0 {
			oldest := sessionCacheOrder[0]
			sessionCacheOrder = sessionCacheOrder[1:]
			if evicted, ok := sessionCache[oldest]; ok {
				delete(sessionCache, oldest)
				evicted.Close()
			}
		}
		globalMu.Unlock()
		return sess, nil, nil
	}

	release := func() {
		sess.Close()
	}
	return sess, release, nil
}
