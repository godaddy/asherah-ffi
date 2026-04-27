package asherah

import (
	"fmt"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

// LogLevel mirrors the Rust log crate's level enum and the C ABI
// ASHERAH_LOG_* constants delivered by the underlying library.
type LogLevel int

const (
	LogTrace LogLevel = 0
	LogDebug LogLevel = 1
	LogInfo  LogLevel = 2
	LogWarn  LogLevel = 3
	LogError LogLevel = 4
)

// String returns the lowercase level name (matches the Rust log crate).
func (l LogLevel) String() string {
	switch l {
	case LogTrace:
		return "trace"
	case LogDebug:
		return "debug"
	case LogInfo:
		return "info"
	case LogWarn:
		return "warn"
	case LogError:
		return "error"
	default:
		return "unknown"
	}
}

// LogEvent is delivered to a registered LogHook for every log record emitted
// by the underlying Rust crates.
type LogEvent struct {
	Level   LogLevel
	Target  string
	Message string
}

// MetricsEventType identifies which observation the underlying engine recorded.
type MetricsEventType int

const (
	MetricEncrypt    MetricsEventType = 0
	MetricDecrypt    MetricsEventType = 1
	MetricStore      MetricsEventType = 2
	MetricLoad       MetricsEventType = 3
	MetricCacheHit   MetricsEventType = 4
	MetricCacheMiss  MetricsEventType = 5
	MetricCacheStale MetricsEventType = 6
)

// String returns the lowercase metric type name.
func (t MetricsEventType) String() string {
	switch t {
	case MetricEncrypt:
		return "encrypt"
	case MetricDecrypt:
		return "decrypt"
	case MetricStore:
		return "store"
	case MetricLoad:
		return "load"
	case MetricCacheHit:
		return "cache_hit"
	case MetricCacheMiss:
		return "cache_miss"
	case MetricCacheStale:
		return "cache_stale"
	default:
		return "unknown"
	}
}

// MetricsEvent is delivered to a registered MetricsHook. Timing events
// (Encrypt/Decrypt/Store/Load) carry DurationNs > 0 and an empty Name; cache
// events (CacheHit/CacheMiss/CacheStale) carry DurationNs == 0 and the cache
// identifier in Name.
type MetricsEvent struct {
	Type       MetricsEventType
	DurationNs uint64
	Name       string
}

// LogHook is the function signature for log callbacks. Implementations must
// be thread-safe — the hook may fire from any goroutine, including ones
// spawned by the underlying Rust runtime. Panics raised inside the hook are
// recovered and silently dropped because propagating a panic across the FFI
// boundary is undefined behavior.
type LogHook func(LogEvent)

// MetricsHook is the function signature for metrics callbacks. Implementations
// must be thread-safe and non-blocking. Panics are recovered and dropped.
type MetricsHook func(MetricsEvent)

// hookState pins the active user callbacks plus their associated purego
// trampoline pointers. Both must outlive the C ABI registration: purego's
// NewCallback never releases its slot, so we reuse the same trampoline across
// set/clear cycles.
type hookState struct {
	mu sync.Mutex

	logCallback   LogHook
	logTrampoline uintptr

	metricsCallback   MetricsHook
	metricsTrampoline uintptr
}

var hooks hookState

// FFI entry points populated by loadHookSymbols.
var (
	fnSetLogHook       func(callback uintptr, userData uintptr) int
	fnClearLogHook     func() int
	fnSetMetricsHook   func(callback uintptr, userData uintptr) int
	fnClearMetricsHook func() int
)

// cstr reads a NUL-terminated C string at the given uintptr without using
// cgo. Bounded so a corrupted pointer doesn't read forever.
func cstr(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}
	const maxLen = 64 * 1024
	var buf []byte
	for i := uintptr(0); i < maxLen; i++ {
		b := *(*byte)(unsafe.Pointer(ptr + i))
		if b == 0 {
			break
		}
		buf = append(buf, b)
	}
	return string(buf)
}

// SetLogHook installs callback to receive every log record emitted by the
// underlying Asherah crates. Replaces any previously installed hook. Pass nil
// to clear (equivalent to ClearLogHook).
func SetLogHook(callback LogHook) error {
	if err := ensureLoaded(); err != nil {
		return err
	}
	if callback == nil {
		return ClearLogHook()
	}

	hooks.mu.Lock()
	defer hooks.mu.Unlock()

	hooks.logCallback = callback
	if hooks.logTrampoline == 0 {
		hooks.logTrampoline = purego.NewCallback(logTrampoline)
	}
	if rc := fnSetLogHook(hooks.logTrampoline, 0); rc != 0 {
		return fmt.Errorf("asherah-go: SetLogHook failed (rc=%d): %s", rc, lastErrorMessage())
	}
	return nil
}

// ClearLogHook removes the active log hook, if any. Idempotent.
func ClearLogHook() error {
	if err := ensureLoaded(); err != nil {
		return err
	}
	hooks.mu.Lock()
	defer hooks.mu.Unlock()
	if fnClearLogHook != nil {
		fnClearLogHook()
	}
	hooks.logCallback = nil
	return nil
}

// SetMetricsHook installs callback to receive every metrics event emitted by
// the underlying engine. Installing a hook implicitly enables the global
// metrics gate; clearing it disables the gate. Pass nil to clear.
func SetMetricsHook(callback MetricsHook) error {
	if err := ensureLoaded(); err != nil {
		return err
	}
	if callback == nil {
		return ClearMetricsHook()
	}

	hooks.mu.Lock()
	defer hooks.mu.Unlock()

	hooks.metricsCallback = callback
	if hooks.metricsTrampoline == 0 {
		hooks.metricsTrampoline = purego.NewCallback(metricsTrampoline)
	}
	if rc := fnSetMetricsHook(hooks.metricsTrampoline, 0); rc != 0 {
		return fmt.Errorf("asherah-go: SetMetricsHook failed (rc=%d): %s", rc, lastErrorMessage())
	}
	return nil
}

// ClearMetricsHook removes the active metrics hook and disables the metrics
// gate. Idempotent.
func ClearMetricsHook() error {
	if err := ensureLoaded(); err != nil {
		return err
	}
	hooks.mu.Lock()
	defer hooks.mu.Unlock()
	if fnClearMetricsHook != nil {
		fnClearMetricsHook()
	}
	hooks.metricsCallback = nil
	return nil
}

// logTrampoline is the C-callable function pointer that asherah-ffi invokes.
// Per the C ABI, the string pointers are valid only for the duration of the
// call; we copy into Go strings before dispatching.
func logTrampoline(userData uintptr, level int32, target uintptr, message uintptr) uintptr {
	defer func() { _ = recover() }()
	cb := hooks.logCallback
	if cb == nil {
		return 0
	}
	cb(LogEvent{
		Level:   LogLevel(level),
		Target:  cstr(target),
		Message: cstr(message),
	})
	return 0
}

// metricsTrampoline is the C-callable function pointer for metrics events.
func metricsTrampoline(userData uintptr, eventType int32, durationNs uint64, name uintptr) uintptr {
	defer func() { _ = recover() }()
	cb := hooks.metricsCallback
	if cb == nil {
		return 0
	}
	cb(MetricsEvent{
		Type:       MetricsEventType(eventType),
		DurationNs: durationNs,
		Name:       cstr(name),
	})
	return 0
}
