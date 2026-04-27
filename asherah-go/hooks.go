package asherah

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
	"unsafe"

	"github.com/ebitengine/purego"
)

// LevelTrace is one step below [slog.LevelDebug]. The Rust log crate has a
// TRACE level that stdlib slog does not; Asherah surfaces those records as
// [LevelTrace] so callers can filter on it via slog's standard
// [slog.Leveler] machinery.
const LevelTrace = slog.Level(-8)

// LogEvent is delivered to a registered LogHook for every log record emitted
// by the underlying Rust crates. Level uses [slog.Level] directly so the
// value plugs into any [slog.Handler] without translation.
type LogEvent struct {
	Level   slog.Level
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

// cLevelToSlog maps the C ABI integer level (mirrors Rust log crate) to a
// [slog.Level]. The Rust TRACE has no slog equivalent, so it falls below
// [slog.LevelDebug] as [LevelTrace].
func cLevelToSlog(level int32) slog.Level {
	switch level {
	case 0: // ASHERAH_LOG_TRACE
		return LevelTrace
	case 1: // ASHERAH_LOG_DEBUG
		return slog.LevelDebug
	case 2: // ASHERAH_LOG_INFO
		return slog.LevelInfo
	case 3: // ASHERAH_LOG_WARN
		return slog.LevelWarn
	case 4: // ASHERAH_LOG_ERROR
		return slog.LevelError
	default:
		return slog.LevelError
	}
}

// SetLogHook installs callback to receive every log record emitted by the
// underlying Asherah crates. Replaces any previously installed hook. Pass nil
// to clear (equivalent to ClearLogHook).
//
// To forward records to a [*slog.Logger] use [SetSlogLogger]; to forward
// to a [slog.Handler] directly use [SetSlogHandler].
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

// SetSlogLogger forwards every Asherah log record to the supplied
// [*slog.Logger]. The logger's own enablement check is honoured before each
// record is emitted, so out-of-band records below the logger's threshold
// are dropped without allocation. Replaces any previously installed hook.
//
// The Rust source target (e.g. "asherah::session") is attached as a
// "target" attribute on every record so handlers can route by category.
func SetSlogLogger(logger *slog.Logger) error {
	if logger == nil {
		return ClearLogHook()
	}
	return SetSlogHandler(logger.Handler())
}

// SetSlogHandler forwards every Asherah log record to the supplied
// [slog.Handler]. Use this when you need to wire Asherah into a logging
// pipeline that exposes a Handler rather than a Logger (for example,
// composing handlers with [slog.NewJSONHandler] under a custom dispatcher).
func SetSlogHandler(handler slog.Handler) error {
	if handler == nil {
		return ClearLogHook()
	}
	return SetLogHook(func(event LogEvent) {
		ctx := context.Background()
		if !handler.Enabled(ctx, event.Level) {
			return
		}
		// Use time.Now() rather than the zero time so the record carries a
		// timestamp at the moment the FFI layer dispatched it (the Rust side
		// does not propagate a wall-clock time across the boundary).
		record := slog.NewRecord(time.Now(), event.Level, event.Message, 0)
		record.AddAttrs(slog.String("target", event.Target))
		_ = handler.Handle(ctx, record)
	})
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
		Level:   cLevelToSlog(level),
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
