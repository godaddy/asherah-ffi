// Package asherah provides Go bindings for the Asherah envelope encryption
// library with automatic key rotation.
//
// Asherah uses a layered key hierarchy (system keys, intermediate keys,
// and data row keys) to encrypt data at the application layer. Keys are
// automatically rotated and managed via a configurable KMS backend
// (AWS KMS or static for testing) and metastore (DynamoDB, MySQL,
// Postgres, or in-memory for testing).
//
// This package uses purego for FFI (no CGO required) and loads a prebuilt
// native library at runtime. Install the native library with:
//
//	go run github.com/godaddy/asherah-ffi/asherah-go/cmd/install-native@latest
//
// # Quick Start
//
// Use the global API for simple scripts:
//
//	asherah.Setup(asherah.Config{
//	    ServiceName: "my-service",
//	    ProductID:   "my-product",
//	    Metastore:   "memory",
//	    KMS:         "static",
//	})
//	defer asherah.Shutdown()
//
//	ct, _ := asherah.EncryptString("partition", "secret")
//	pt, _ := asherah.DecryptString("partition", ct)
//
// For applications, use the Factory/Session API for explicit lifecycle
// management and session reuse:
//
//	factory, _ := asherah.NewFactory(cfg)
//	defer factory.Close()
//
//	session, _ := factory.GetSession("partition")
//	defer session.Close()
//
//	ct, _ := session.EncryptString("secret")
//	pt, _ := session.DecryptString(ct)
package asherah
