package asherah

// Canonical godaddy/asherah Go SDK compatibility layer.
// Provides the same SessionFactory/Session/DataRowRecord API surface so that
// existing code can switch to the FFI binding by changing only the import path.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// --- Types matching canonical SDK ---

// DataRowRecord contains the encrypted key and data, matching the canonical
// appencryption.DataRowRecord type.
type DataRowRecord struct {
	Key  *EnvelopeKeyRecord `json:"Key"`
	Data []byte             `json:"Data"`
}

// EnvelopeKeyRecord represents an encrypted key, matching the canonical type.
type EnvelopeKeyRecord struct {
	Revoked       bool     `json:"Revoked,omitempty"`
	Created       int64    `json:"Created"`
	EncryptedKey  []byte   `json:"Key"`
	ParentKeyMeta *KeyMeta `json:"ParentKeyMeta,omitempty"`
}

// KeyMeta contains the key identifier and creation timestamp.
type KeyMeta struct {
	ID      string `json:"KeyId"`
	Created int64  `json:"Created"`
}

// --- Interfaces matching canonical SDK ---

// Encryption defines the canonical encrypt/decrypt interface.
type Encryption interface {
	EncryptPayload(ctx context.Context, data []byte) (*DataRowRecord, error)
	DecryptDataRowRecord(ctx context.Context, d DataRowRecord) ([]byte, error)
	Close() error
}

// KeyManagementService is the canonical KMS interface.
// In the FFI binding, KMS is handled by the native layer.
type KeyManagementService interface {
	EncryptKey(context.Context, []byte) ([]byte, error)
	DecryptKey(context.Context, []byte) ([]byte, error)
}

// Metastore is the canonical metastore interface.
// In the FFI binding, metastore is handled by the native layer.
type Metastore interface {
	Load(ctx context.Context, id string, created int64) (*EnvelopeKeyRecord, error)
	LoadLatest(ctx context.Context, id string) (*EnvelopeKeyRecord, error)
	Store(ctx context.Context, id string, created int64, envelope *EnvelopeKeyRecord) (bool, error)
}

// AEAD is the canonical cipher interface.
type AEAD interface {
	Encrypt(data, key []byte) ([]byte, error)
	Decrypt(data, key []byte) ([]byte, error)
}

// Loader is the canonical data persistence load interface.
type Loader interface {
	Load(ctx context.Context, key any) (*DataRowRecord, error)
}

// Storer is the canonical data persistence store interface.
type Storer interface {
	Store(ctx context.Context, d DataRowRecord) (any, error)
}

// AES256KeySize matches the canonical constant.
const AES256KeySize int = 32

// --- Built-in implementations ---

// StaticKMS is a static key management service for testing.
type StaticKMS struct {
	key string
}

// NewStaticKMS creates a static KMS with the given master key string.
func NewStaticKMS(key string) *StaticKMS {
	return &StaticKMS{key: key}
}

func (s *StaticKMS) EncryptKey(_ context.Context, _ []byte) ([]byte, error) {
	return nil, errors.New("StaticKMS: handled by native layer")
}
func (s *StaticKMS) DecryptKey(_ context.Context, _ []byte) ([]byte, error) {
	return nil, errors.New("StaticKMS: handled by native layer")
}
func (s *StaticKMS) applyConfig(cfg *Config) {
	cfg.KMS = "static"
	hex := fmt.Sprintf("%x", s.key)
	os.Setenv("STATIC_MASTER_KEY_HEX", hex)
}

// InMemoryMetastore is an in-memory metastore marker. Maps to metastore="memory".
type InMemoryMetastore struct{}

func (m *InMemoryMetastore) Load(_ context.Context, _ string, _ int64) (*EnvelopeKeyRecord, error) {
	return nil, errors.New("InMemoryMetastore: handled by native layer")
}
func (m *InMemoryMetastore) LoadLatest(_ context.Context, _ string) (*EnvelopeKeyRecord, error) {
	return nil, errors.New("InMemoryMetastore: handled by native layer")
}
func (m *InMemoryMetastore) Store(_ context.Context, _ string, _ int64, _ *EnvelopeKeyRecord) (bool, error) {
	return false, errors.New("InMemoryMetastore: handled by native layer")
}

// --- CryptoPolicy ---

// CryptoPolicy matches the canonical policy struct. Settings are mapped to
// the native FFI config.
type CryptoPolicy struct {
	CacheSystemKeys            bool
	CacheIntermediateKeys      bool
	CacheSessions              bool
	SharedIntermediateKeyCache bool
	SessionCacheMaxSize        int
	SessionCacheExpireMillis   int64
	ExpireKeyAfterMillis       int64
	RevokeCheckMillis          int64
}

// NewCryptoPolicy creates a default crypto policy (keys never expire).
func NewCryptoPolicy() *CryptoPolicy {
	return &CryptoPolicy{
		CacheSystemKeys:       true,
		CacheIntermediateKeys: true,
	}
}

// --- Canonical Config (wraps our Config) ---

// CanonicalConfig matches the canonical appencryption.Config struct.
type CanonicalConfig struct {
	Service string
	Product string
	Policy  *CryptoPolicy
}

// --- SessionFactory ---

// SessionFactory provides the canonical factory API. Wraps our FFI Factory.
type SessionFactory struct {
	factory *Factory
	policy  *CryptoPolicy
}

// FactoryOption configures additional SessionFactory options.
type FactoryOption func(*SessionFactory)

// WithMetrics enables or disables metrics (accepted for API compat; metrics handled by native layer).
func WithMetrics(_ bool) FactoryOption {
	return func(_ *SessionFactory) {}
}

// NewSessionFactory creates a new SessionFactory matching the canonical API signature.
// The metastore, kms, and crypto arguments are used to derive native config.
func NewSessionFactory(config *CanonicalConfig, store Metastore, kms KeyManagementService, crypto AEAD, opts ...FactoryOption) *SessionFactory {
	if config.Policy == nil {
		config.Policy = NewCryptoPolicy()
	}

	cfg := Config{
		ServiceName: config.Service,
		ProductID:   config.Product,
		Metastore:   "memory",
	}

	// Apply metastore config
	switch store.(type) {
	case *InMemoryMetastore:
		cfg.Metastore = "memory"
	}

	// Apply KMS config
	if sk, ok := kms.(*StaticKMS); ok {
		sk.applyConfig(&cfg)
	}

	// Apply crypto policy
	policy := config.Policy
	if policy.CacheSessions {
		t := true
		cfg.EnableSessionCaching = &t
		if policy.SessionCacheMaxSize > 0 {
			cfg.SessionCacheMaxSize = &policy.SessionCacheMaxSize
		}
	} else {
		f := false
		cfg.EnableSessionCaching = &f
	}
	if policy.ExpireKeyAfterMillis > 0 {
		secs := policy.ExpireKeyAfterMillis / 1000
		cfg.ExpireAfter = &secs
	}
	if policy.RevokeCheckMillis > 0 {
		secs := policy.RevokeCheckMillis / 1000
		cfg.CheckInterval = &secs
	}

	factory, err := NewFactory(cfg)
	if err != nil {
		panic(fmt.Sprintf("asherah: NewSessionFactory failed: %v", err))
	}

	sf := &SessionFactory{
		factory: factory,
		policy:  policy,
	}
	for _, opt := range opts {
		opt(sf)
	}
	return sf
}

// GetSession returns a session for the given partition ID.
func (f *SessionFactory) GetSession(id string) (*CompatSession, error) {
	if id == "" {
		return nil, errors.New("partition id cannot be empty")
	}
	sess, err := f.factory.GetSession(id)
	if err != nil {
		return nil, err
	}
	return &CompatSession{inner: sess}, nil
}

// Close releases factory resources.
func (f *SessionFactory) Close() error {
	f.factory.Close()
	return nil
}

// --- CompatSession wraps our Session with canonical method signatures ---

// CompatSession provides the canonical Session API surface.
type CompatSession struct {
	inner *Session
}

// Encrypt encrypts data and returns a DataRowRecord.
// The context parameter is accepted for API compatibility but not used
// (the native layer does not support cancellation).
func (s *CompatSession) Encrypt(_ context.Context, data []byte) (*DataRowRecord, error) {
	jsonBytes, err := s.inner.Encrypt(data)
	if err != nil {
		return nil, err
	}
	var drr DataRowRecord
	if err := json.Unmarshal(jsonBytes, &drr); err != nil {
		return nil, fmt.Errorf("asherah: failed to parse DataRowRecord: %w", err)
	}
	return &drr, nil
}

// Decrypt decrypts a DataRowRecord and returns the original plaintext.
func (s *CompatSession) Decrypt(_ context.Context, d DataRowRecord) ([]byte, error) {
	jsonBytes, err := json.Marshal(&d)
	if err != nil {
		return nil, fmt.Errorf("asherah: failed to serialize DataRowRecord: %w", err)
	}
	return s.inner.Decrypt(jsonBytes)
}

// Load loads a DataRowRecord from the store and decrypts it.
func (s *CompatSession) Load(ctx context.Context, key any, store Loader) ([]byte, error) {
	drr, err := store.Load(ctx, key)
	if err != nil {
		return nil, err
	}
	return s.Decrypt(ctx, *drr)
}

// Store encrypts a payload and stores the DataRowRecord.
func (s *CompatSession) Store(ctx context.Context, payload []byte, store Storer) (any, error) {
	drr, err := s.Encrypt(ctx, payload)
	if err != nil {
		return nil, err
	}
	return store.Store(ctx, *drr)
}

// Close releases session resources.
func (s *CompatSession) Close() error {
	s.inner.Close()
	return nil
}
