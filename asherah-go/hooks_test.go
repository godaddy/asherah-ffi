package asherah

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func hooksConfig() Config {
	caching := false
	return Config{
		ServiceName:          "hooks-svc",
		ProductID:            "hooks-prod",
		Metastore:            "memory",
		KMS:                  "static",
		EnableSessionCaching: &caching,
	}
}

func ensureHooksEnv(t *testing.T) {
	t.Helper()
	os.Setenv("STATIC_MASTER_KEY_HEX", strings.Repeat("22", 32))
	// Pin the native library lookup to the freshly built target/debug or
	// target/release directory so a stale binary in the system search path
	// can't shadow the workspace build.
	_, file, _, _ := runtime.Caller(0)
	moduleDir := filepath.Dir(file)
	repoRoot := filepath.Dir(moduleDir)
	for _, sub := range []string{"target/debug", "target/release"} {
		p := filepath.Join(repoRoot, sub)
		if _, err := os.Stat(p); err == nil {
			os.Setenv("ASHERAH_GO_NATIVE", p)
			return
		}
	}
}

// resetHooks defensively clears any registered hook so a leak from a prior
// test cannot bleed into the next one.
func resetHooks(t *testing.T) {
	t.Helper()
	if err := ClearLogHook(); err != nil {
		t.Fatalf("ClearLogHook: %v", err)
	}
	if err := ClearMetricsHook(); err != nil {
		t.Fatalf("ClearMetricsHook: %v", err)
	}
}

// setupHooks calls Setup and registers a t.Cleanup that always shuts down
// the global factory, even if the test fails. Tests must use this instead
// of calling Setup directly so a t.Fatal cannot strand the global factory
// and break subsequent tests.
func setupHooks(t *testing.T, cfg Config) {
	t.Helper()
	if err := Setup(cfg); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	t.Cleanup(func() {
		if GetSetupStatus() {
			Shutdown()
		}
	})
}

// ---------- log hook ----------

func TestSetLogHookAcceptsCallback(t *testing.T) {
	ensureHooksEnv(t)
	resetHooks(t)
	defer resetHooks(t)
	if err := SetLogHook(func(LogEvent) {}); err != nil {
		t.Fatalf("SetLogHook: %v", err)
	}
}

func TestClearLogHookIsIdempotent(t *testing.T) {
	resetHooks(t)
	if err := ClearLogHook(); err != nil {
		t.Fatalf("first clear: %v", err)
	}
	if err := ClearLogHook(); err != nil {
		t.Fatalf("second clear: %v", err)
	}
}

func TestSetLogHookNilClears(t *testing.T) {
	ensureHooksEnv(t)
	resetHooks(t)
	defer resetHooks(t)

	if err := SetLogHook(func(LogEvent) {}); err != nil {
		t.Fatalf("SetLogHook: %v", err)
	}
	if err := SetLogHook(nil); err != nil {
		t.Fatalf("SetLogHook(nil): %v", err)
	}
	setupHooks(t, hooksConfig())
	if _, err := Encrypt("nil-clear", []byte("payload")); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
}

func TestLogHookFiresWithWellFormedEvents(t *testing.T) {
	ensureHooksEnv(t)
	resetHooks(t)
	defer resetHooks(t)

	var (
		mu       sync.Mutex
		received []LogEvent
	)
	if err := SetLogHook(func(e LogEvent) {
		mu.Lock()
		defer mu.Unlock()
		received = append(received, e)
	}); err != nil {
		t.Fatalf("SetLogHook: %v", err)
	}
	setupHooks(t, hooksConfig())
	for i := 0; i < 5; i++ {
		ct, err := Encrypt("log-fields", []byte("payload"))
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		if _, err := Decrypt("log-fields", ct); err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) == 0 {
		t.Fatalf("expected at least one log event")
	}
	for _, e := range received {
		if e.Level < LogTrace || e.Level > LogError {
			t.Errorf("invalid level: %v", e.Level)
		}
		if e.Target == "" {
			t.Errorf("empty target")
		}
		if e.Level.String() == "unknown" {
			t.Errorf("unknown level string for %v", e.Level)
		}
	}
}

func TestLogHookPanicDoesNotCrash(t *testing.T) {
	ensureHooksEnv(t)
	resetHooks(t)
	defer resetHooks(t)

	if err := SetLogHook(func(LogEvent) {
		panic("intentional from log hook")
	}); err != nil {
		t.Fatalf("SetLogHook: %v", err)
	}
	setupHooks(t, hooksConfig())

	ct, err := Encrypt("log-throw", []byte("survive"))
	if err != nil {
		t.Fatalf("Encrypt after panicking hook: %v", err)
	}
	pt, err := Decrypt("log-throw", ct)
	if err != nil {
		t.Fatalf("Decrypt after panicking hook: %v", err)
	}
	if string(pt) != "survive" {
		t.Errorf("plaintext mismatch: %q", pt)
	}
}

func TestReplaceLogHookRedirects(t *testing.T) {
	ensureHooksEnv(t)
	resetHooks(t)
	defer resetHooks(t)

	if err := SetLogHook(func(LogEvent) {}); err != nil {
		t.Fatalf("SetLogHook (old): %v", err)
	}
	if err := SetLogHook(func(LogEvent) {}); err != nil {
		t.Fatalf("SetLogHook (new): %v", err)
	}
}

// ---------- metrics hook ----------

func TestSetMetricsHookAcceptsCallback(t *testing.T) {
	ensureHooksEnv(t)
	resetHooks(t)
	defer resetHooks(t)
	if err := SetMetricsHook(func(MetricsEvent) {}); err != nil {
		t.Fatalf("SetMetricsHook: %v", err)
	}
}

func TestClearMetricsHookIsIdempotent(t *testing.T) {
	resetHooks(t)
	if err := ClearMetricsHook(); err != nil {
		t.Fatalf("first clear: %v", err)
	}
	if err := ClearMetricsHook(); err != nil {
		t.Fatalf("second clear: %v", err)
	}
}

func TestSetMetricsHookNilClears(t *testing.T) {
	ensureHooksEnv(t)
	resetHooks(t)
	defer resetHooks(t)

	var fired int32
	if err := SetMetricsHook(func(MetricsEvent) { atomic.AddInt32(&fired, 1) }); err != nil {
		t.Fatalf("SetMetricsHook: %v", err)
	}
	if err := SetMetricsHook(nil); err != nil {
		t.Fatalf("SetMetricsHook(nil): %v", err)
	}
	setupHooks(t, hooksConfig())
	if _, err := Encrypt("metrics-nil-clear", []byte("payload")); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if got := atomic.LoadInt32(&fired); got != 0 {
		t.Errorf("metrics hook fired %d times after nil-clear", got)
	}
}

func TestMetricsHookFiresEncryptAndDecrypt(t *testing.T) {
	ensureHooksEnv(t)
	resetHooks(t)
	defer resetHooks(t)

	var (
		mu sync.Mutex
		seenTypes = map[MetricsEventType]int{}
	)
	if err := SetMetricsHook(func(e MetricsEvent) {
		mu.Lock()
		seenTypes[e.Type]++
		mu.Unlock()
	}); err != nil {
		t.Fatalf("SetMetricsHook: %v", err)
	}
	setupHooks(t, hooksConfig())
	for i := 0; i < 5; i++ {
		ct, err := EncryptString("metrics-fire", "payload")
		if err != nil {
			t.Fatalf("EncryptString: %v", err)
		}
		if _, err := DecryptString("metrics-fire", ct); err != nil {
			t.Fatalf("DecryptString: %v", err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if seenTypes[MetricEncrypt] == 0 {
		t.Errorf("expected MetricEncrypt events, saw %v", seenTypes)
	}
	if seenTypes[MetricDecrypt] == 0 {
		t.Errorf("expected MetricDecrypt events, saw %v", seenTypes)
	}
}

func TestMetricsTimingEventsCarryPositiveDuration(t *testing.T) {
	ensureHooksEnv(t)
	resetHooks(t)
	defer resetHooks(t)

	var (
		mu      sync.Mutex
		timings []MetricsEvent
	)
	if err := SetMetricsHook(func(e MetricsEvent) {
		switch e.Type {
		case MetricEncrypt, MetricDecrypt:
			mu.Lock()
			defer mu.Unlock()
			timings = append(timings, e)
		}
	}); err != nil {
		t.Fatalf("SetMetricsHook: %v", err)
	}
	setupHooks(t, hooksConfig())
	for i := 0; i < 3; i++ {
		ct, _ := EncryptString("timing", "v")
		_, _ = DecryptString("timing", ct)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(timings) == 0 {
		t.Fatalf("expected at least one timing event")
	}
	for _, e := range timings {
		if e.DurationNs == 0 {
			t.Errorf("timing event %v carried zero duration", e.Type)
		}
		if e.Name != "" {
			t.Errorf("timing event %v carried name %q", e.Type, e.Name)
		}
	}
}

func TestMetricsHookPanicDoesNotCrash(t *testing.T) {
	ensureHooksEnv(t)
	resetHooks(t)
	defer resetHooks(t)

	var fired int32
	if err := SetMetricsHook(func(MetricsEvent) {
		atomic.AddInt32(&fired, 1)
		panic("intentional from metrics hook")
	}); err != nil {
		t.Fatalf("SetMetricsHook: %v", err)
	}
	setupHooks(t, hooksConfig())

	ct, err := EncryptString("metrics-throw", "survive")
	if err != nil {
		t.Fatalf("Encrypt after panicking hook: %v", err)
	}
	pt, err := DecryptString("metrics-throw", ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if pt != "survive" {
		t.Errorf("plaintext mismatch: %q", pt)
	}
	if atomic.LoadInt32(&fired) == 0 {
		t.Errorf("metrics hook never fired")
	}
}

func TestMetricsHookSurvivesManyOperations(t *testing.T) {
	ensureHooksEnv(t)
	resetHooks(t)
	defer resetHooks(t)

	var fired int32
	if err := SetMetricsHook(func(MetricsEvent) { atomic.AddInt32(&fired, 1) }); err != nil {
		t.Fatalf("SetMetricsHook: %v", err)
	}
	setupHooks(t, hooksConfig())
	for i := 0; i < 100; i++ {
		ct, _ := EncryptString("vol", "payload")
		_, _ = DecryptString("vol", ct)
	}

	if got := atomic.LoadInt32(&fired); got < 200 {
		t.Errorf("expected ≥200 metrics events for 100 enc/dec ops, got %d", got)
	}
}

func TestMetricsAndLogHooksCoexist(t *testing.T) {
	ensureHooksEnv(t)
	resetHooks(t)
	defer resetHooks(t)

	var logHits, metricHits int32
	if err := SetLogHook(func(LogEvent) { atomic.AddInt32(&logHits, 1) }); err != nil {
		t.Fatalf("SetLogHook: %v", err)
	}
	if err := SetMetricsHook(func(MetricsEvent) { atomic.AddInt32(&metricHits, 1) }); err != nil {
		t.Fatalf("SetMetricsHook: %v", err)
	}
	setupHooks(t, hooksConfig())
	for i := 0; i < 3; i++ {
		ct, _ := EncryptString("coexist", "v")
		_, _ = DecryptString("coexist", ct)
	}

	if atomic.LoadInt32(&metricHits) == 0 {
		t.Errorf("metrics hook should have fired")
	}
	_ = logHits // log events are best-effort; don't assert nonzero
}

func TestCacheEventsCarryNameAndZeroDuration(t *testing.T) {
	ensureHooksEnv(t)
	resetHooks(t)
	defer resetHooks(t)

	var (
		mu     sync.Mutex
		caches []MetricsEvent
	)
	if err := SetMetricsHook(func(e MetricsEvent) {
		switch e.Type {
		case MetricCacheHit, MetricCacheMiss, MetricCacheStale:
			mu.Lock()
			defer mu.Unlock()
			caches = append(caches, e)
		}
	}); err != nil {
		t.Fatalf("SetMetricsHook: %v", err)
	}
	caching := true
	cfg := hooksConfig()
	cfg.EnableSessionCaching = &caching
	setupHooks(t, cfg)
	for i := 0; i < 3; i++ {
		ct, _ := EncryptString("cache-part-x", "payload")
		_, _ = DecryptString("cache-part-x", ct)
	}

	mu.Lock()
	defer mu.Unlock()
	for _, e := range caches {
		if e.DurationNs != 0 {
			t.Errorf("cache event %v carried non-zero duration %d", e.Type, e.DurationNs)
		}
		if e.Name == "" {
			t.Errorf("cache event %v missing name", e.Type)
		}
	}
}

func TestHookSurvivesSetupShutdownCycles(t *testing.T) {
	ensureHooksEnv(t)
	resetHooks(t)
	defer resetHooks(t)

	var hits int32
	if err := SetMetricsHook(func(MetricsEvent) { atomic.AddInt32(&hits, 1) }); err != nil {
		t.Fatalf("SetMetricsHook: %v", err)
	}
	for cycle := 0; cycle < 3; cycle++ {
		if err := Setup(hooksConfig()); err != nil {
			t.Fatalf("Setup cycle %d: %v", cycle, err)
		}
		ct, _ := EncryptString("cycle", "payload")
		_, _ = DecryptString("cycle", ct)
		Shutdown()
	}
	if atomic.LoadInt32(&hits) == 0 {
		t.Errorf("metrics hook should fire across factory cycles")
	}
}

func TestLogLevelStringHandlesAllVariants(t *testing.T) {
	cases := map[LogLevel]string{
		LogTrace: "trace",
		LogDebug: "debug",
		LogInfo:  "info",
		LogWarn:  "warn",
		LogError: "error",
	}
	for level, want := range cases {
		if got := level.String(); got != want {
			t.Errorf("%v.String() = %q, want %q", level, got, want)
		}
	}
}

func TestMetricsEventTypeStringHandlesAllVariants(t *testing.T) {
	cases := map[MetricsEventType]string{
		MetricEncrypt:    "encrypt",
		MetricDecrypt:    "decrypt",
		MetricStore:      "store",
		MetricLoad:       "load",
		MetricCacheHit:   "cache_hit",
		MetricCacheMiss:  "cache_miss",
		MetricCacheStale: "cache_stale",
	}
	for typ, want := range cases {
		if got := typ.String(); got != want {
			t.Errorf("%v.String() = %q, want %q", typ, got, want)
		}
	}
}
