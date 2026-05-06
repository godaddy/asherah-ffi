package asherah

import (
	"container/list"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
)

// Global (module-level) API — convenience wrappers around Factory/Session.

const defaultSessionCacheMaxSize = 1000

// sessionCacheEntry holds the partition id alongside the session so an
// eviction of the LRU element can clean up the map index in O(1).
type sessionCacheEntry struct {
	partition string
	session   *Session
}

var (
	// globalMu protects globalFactory + the cache configuration
	// (sessionCaching, sessionCacheMaxSize). It is held briefly with
	// RLock for the lookups on the encrypt/decrypt hot path.
	globalMu      sync.RWMutex
	globalFactory *Factory
	// sessionCache is a bounded LRU. The map gives O(1) lookup; the list
	// orders entries by recency. On hit we move the element to the back
	// (most-recently-used); on overflow we evict the front (least-
	// recently-used). The previous implementation was insertion-ordered
	// FIFO, which evicts hot entries that were re-used after insertion.
	//
	// The cache is guarded by `sessionMu` (a `sync.Mutex`, not the
	// global RWMutex). The original implementation took a write lock
	// on `globalMu` for every cache hit just to call
	// `sessionLRU.MoveToBack`, which serialized every encrypt/decrypt
	// behind a single global writer regardless of whether the caller
	// touched configuration. Splitting the locks lets the read-heavy
	// config-lookup path stay on the RWMutex while the cache mutation
	// uses its own dedicated lock — concurrent encrypts on different
	// partitions only contend with each other on the cache lock, not
	// with shutdown/setup operations. T-finding "globalMu write lock
	// on every cache hit just for MoveToBack" in
	// `docs/review-2026-05-05-findings.md`.
	sessionMu           sync.Mutex
	sessionCache        map[string]*list.Element
	sessionLRU          *list.List
	sessionCacheMaxSize int
	sessionCaching      bool
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
	// Lock order: `globalMu` first (already held), then `sessionMu`.
	// The cache state is touched by `acquireSession` under `sessionMu`
	// only after observing a non-nil `globalFactory` under
	// `globalMu.RLock()`, so initializing the cache here while holding
	// both prevents an `acquireSession` from racing into a half-built
	// `sessionCache`/`sessionLRU` pair.
	sessionMu.Lock()
	if sessionCaching {
		sessionCache = make(map[string]*list.Element)
		sessionLRU = list.New()
	} else {
		sessionCache = nil
		sessionLRU = nil
	}
	sessionMu.Unlock()

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
	sessionCacheMaxSize = defaultSessionCacheMaxSize
	sessionMu.Lock()
	sessionCache = make(map[string]*list.Element)
	sessionLRU = list.New()
	sessionMu.Unlock()
	return nil
}

// Shutdown releases the global factory and any cached sessions.
func Shutdown() {
	globalMu.Lock()
	factory := globalFactory
	globalFactory = nil
	sessionCaching = false
	// Drain the cache under `sessionMu`. Lock order: `globalMu` first
	// (already held), then `sessionMu` — see the comment on the
	// declarations and matching order in `Setup` and `acquireSession`.
	sessionMu.Lock()
	var sessions []*Session
	if sessionLRU != nil {
		sessions = make([]*Session, 0, sessionLRU.Len())
		for e := sessionLRU.Front(); e != nil; e = e.Next() {
			sessions = append(sessions, e.Value.(sessionCacheEntry).session)
		}
	}
	sessionCache = nil
	sessionLRU = nil
	sessionMu.Unlock()
	globalMu.Unlock()

	for _, sess := range sessions {
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
		sessionMu.Lock()
		if elem, ok := sessionCache[partition]; ok {
			// LRU hit: move to back (most-recently-used).
			sessionLRU.MoveToBack(elem)
			sess := elem.Value.(sessionCacheEntry).session
			sessionMu.Unlock()
			return sess, nil, nil
		}
		sessionMu.Unlock()
	}

	sess, err := factory.GetSession(partition)
	if err != nil {
		return nil, nil, err
	}

	if caching {
		var evicted *Session
		sessionMu.Lock()
		if elem, ok := sessionCache[partition]; ok {
			// Lost the race — another goroutine inserted while we created.
			sessionLRU.MoveToBack(elem)
			existing := elem.Value.(sessionCacheEntry).session
			sessionMu.Unlock()
			sess.Close()
			return existing, nil, nil
		}
		if sessionCache == nil {
			sessionCache = make(map[string]*list.Element)
			sessionLRU = list.New()
		}
		entry := sessionCacheEntry{partition: partition, session: sess}
		sessionCache[partition] = sessionLRU.PushBack(entry)
		// Evict the LRU entry if we're now over the bound.
		if sessionLRU.Len() > sessionCacheMaxSize {
			front := sessionLRU.Front()
			if front != nil {
				lruEntry := front.Value.(sessionCacheEntry)
				sessionLRU.Remove(front)
				delete(sessionCache, lruEntry.partition)
				evicted = lruEntry.session
			}
		}
		sessionMu.Unlock()
		// Close evicted session outside the lock — Close hits the FFI
		// and we don't want to serialize all encrypts behind eviction.
		if evicted != nil {
			evicted.Close()
		}
		return sess, nil, nil
	}

	release := func() {
		sess.Close()
	}
	return sess, release, nil
}
