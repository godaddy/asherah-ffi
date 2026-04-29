# Framework integration

How to wire Asherah into common Go frameworks. The pattern is
consistent: **build the factory at program startup, defer cleanup,
use sessions per request/task.**

Go doesn't have a DI framework convention; the idiomatic pattern is
to construct the factory in `main` and pass it to handlers/services
via struct fields or function parameters.

## net/http

```go
package main

import (
    "encoding/json"
    "log/slog"
    "net/http"

    asherah "github.com/godaddy/asherah-ffi/asherah-go"
)

type Server struct {
    factory *asherah.Factory
}

func main() {
    factory, err := asherah.NewFactory(buildConfig())
    if err != nil { log.Fatal(err) }
    defer factory.Close()

    _ = asherah.SetSlogLogger(slog.Default())

    srv := &Server{factory: factory}

    mux := http.NewServeMux()
    mux.HandleFunc("POST /protect", srv.handleProtect)
    mux.HandleFunc("POST /unprotect", srv.handleUnprotect)

    if err := http.ListenAndServe(":8080", mux); err != nil {
        log.Fatal(err)
    }
}

func (s *Server) handleProtect(w http.ResponseWriter, r *http.Request) {
    var body struct {
        TenantID  string `json:"tenant_id"`
        Plaintext string `json:"plaintext"`
    }
    if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    session, err := s.factory.GetSession(body.TenantID)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer session.Close()

    ct, err := session.EncryptString(body.Plaintext)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    json.NewEncoder(w).Encode(map[string]string{"token": ct})
}
```

## Gin

```go
import (
    "github.com/gin-gonic/gin"
    asherah "github.com/godaddy/asherah-ffi/asherah-go"
)

func main() {
    factory, err := asherah.NewFactory(buildConfig())
    if err != nil { log.Fatal(err) }
    defer factory.Close()

    r := gin.Default()
    r.Use(func(c *gin.Context) {
        c.Set("asherah_factory", factory)
        c.Next()
    })

    r.POST("/protect", func(c *gin.Context) {
        var body struct {
            TenantID  string `json:"tenant_id" binding:"required"`
            Plaintext string `json:"plaintext" binding:"required"`
        }
        if err := c.ShouldBindJSON(&body); err != nil {
            c.JSON(400, gin.H{"error": err.Error()})
            return
        }

        f := c.MustGet("asherah_factory").(*asherah.Factory)
        session, err := f.GetSession(body.TenantID)
        if err != nil {
            c.JSON(500, gin.H{"error": err.Error()})
            return
        }
        defer session.Close()

        ct, err := session.EncryptString(body.Plaintext)
        if err != nil {
            c.JSON(500, gin.H{"error": err.Error()})
            return
        }
        c.JSON(200, gin.H{"token": ct})
    })

    r.Run(":8080")
}
```

## Echo

```go
import (
    "github.com/labstack/echo/v4"
    asherah "github.com/godaddy/asherah-ffi/asherah-go"
)

func main() {
    factory, err := asherah.NewFactory(buildConfig())
    if err != nil { log.Fatal(err) }
    defer factory.Close()

    e := echo.New()
    e.POST("/protect", func(c echo.Context) error {
        var body struct {
            TenantID  string `json:"tenant_id"`
            Plaintext string `json:"plaintext"`
        }
        if err := c.Bind(&body); err != nil {
            return echo.NewHTTPError(400, err.Error())
        }

        session, err := factory.GetSession(body.TenantID)
        if err != nil { return err }
        defer session.Close()

        ct, err := session.EncryptString(body.Plaintext)
        if err != nil { return err }
        return c.JSON(200, map[string]string{"token": ct})
    })

    e.Logger.Fatal(e.Start(":8080"))
}
```

## chi

```go
import (
    "github.com/go-chi/chi/v5"
    asherah "github.com/godaddy/asherah-ffi/asherah-go"
)

func main() {
    factory, err := asherah.NewFactory(buildConfig())
    if err != nil { log.Fatal(err) }
    defer factory.Close()

    r := chi.NewRouter()
    r.Post("/protect", protectHandler(factory))

    http.ListenAndServe(":8080", r)
}

func protectHandler(factory *asherah.Factory) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // ... same shape as net/http example
    }
}
```

## gRPC

```go
import (
    "google.golang.org/grpc"
    asherah "github.com/godaddy/asherah-ffi/asherah-go"
)

type EnvelopeServer struct {
    pb.UnimplementedEnvelopeServer
    factory *asherah.Factory
}

func (s *EnvelopeServer) Protect(ctx context.Context, req *pb.ProtectRequest) (*pb.ProtectResponse, error) {
    session, err := s.factory.GetSession(req.TenantId)
    if err != nil { return nil, err }
    defer session.Close()

    ct, err := session.EncryptString(req.Plaintext)
    if err != nil { return nil, err }
    return &pb.ProtectResponse{Token: ct}, nil
}

func main() {
    factory, _ := asherah.NewFactory(buildConfig())
    defer factory.Close()

    srv := grpc.NewServer()
    pb.RegisterEnvelopeServer(srv, &EnvelopeServer{factory: factory})

    lis, _ := net.Listen("tcp", ":50051")
    srv.Serve(lis)
}
```

## AWS Lambda (Go runtime)

Build the factory at `init()` time (or as a package-level variable
initializer) so it survives container reuse:

```go
package main

import (
    "context"
    "encoding/json"
    "log"
    "os"

    "github.com/aws/aws-lambda-go/lambda"
    asherah "github.com/godaddy/asherah-ffi/asherah-go"
)

// Initialized once per cold start, reused across warm invocations.
var factory *asherah.Factory

func init() {
    var err error
    factory, err = asherah.NewFactory(asherah.Config{
        ServiceName: os.Getenv("SERVICE_NAME"),
        ProductID:   os.Getenv("PRODUCT_ID"),
        Metastore:   "dynamodb",
        // ... rest of config ...
    })
    if err != nil { log.Fatal(err) }
}

type Event struct {
    TenantID string `json:"tenantId"`
    Payload  string `json:"payload"`
}

func handler(ctx context.Context, event Event) (map[string]string, error) {
    session, err := factory.GetSession(event.TenantID)
    if err != nil { return nil, err }
    defer session.Close()

    token, err := session.EncryptString(event.Payload)
    if err != nil { return nil, err }
    return map[string]string{"token": token}, nil
}

func main() { lambda.Start(handler) }
```

Lambda doesn't reliably run shutdown hooks on container freeze — the
factory's resources are released when the Go process exits. No
explicit cleanup required.

## Graceful shutdown

For long-running services, handle SIGTERM/SIGINT to drain in-flight
requests before closing the factory:

```go
ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
defer stop()

server := &http.Server{Addr: ":8080", Handler: mux}

go func() {
    <-ctx.Done()
    shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    server.Shutdown(shutdownCtx)
    factory.Close()  // after http.Server has drained
}()

if err := server.ListenAndServe(); err != http.ErrServerClosed {
    log.Fatal(err)
}
```

## slog integration

Asherah exposes log records via `LogEvent` with a `slog.Level` directly:

```go
slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
_ = asherah.SetSlogLogger(slog.Default())
```

`SetSlogLogger` wires the binding's log records through the supplied
`*slog.Logger`. The handler's level filtering applies.

For non-slog loggers (zap, zerolog, logrus), use the callback API:

```go
import "go.uber.org/zap"

logger, _ := zap.NewProduction()
defer logger.Sync()

_ = asherah.SetLogHook(func(e asherah.LogEvent) {
    f := logger.Info
    switch e.Level {
    case slog.LevelDebug: f = logger.Debug
    case slog.LevelWarn:  f = logger.Warn
    case slog.LevelError: f = logger.Error
    }
    f(e.Message, zap.String("target", e.Target))
})
```

## Prometheus / OpenTelemetry metrics

```go
import "github.com/prometheus/client_golang/prometheus"

encryptHist := prometheus.NewHistogram(prometheus.HistogramOpts{
    Name: "asherah_encrypt_duration_seconds",
})
decryptHist := prometheus.NewHistogram(prometheus.HistogramOpts{
    Name: "asherah_decrypt_duration_seconds",
})
cacheHits := prometheus.NewCounterVec(prometheus.CounterOpts{
    Name: "asherah_cache_hits_total",
}, []string{"cache"})

prometheus.MustRegister(encryptHist, decryptHist, cacheHits)

_ = asherah.SetMetricsHook(func(e asherah.MetricsEvent) {
    switch e.Type {
    case "encrypt":   encryptHist.Observe(float64(e.DurationNs) / 1e9)
    case "decrypt":   decryptHist.Observe(float64(e.DurationNs) / 1e9)
    case "cache_hit": cacheHits.WithLabelValues(e.Name).Inc()
    // store/load/cache_miss/cache_stale similarly
    }
})
```

For OpenTelemetry's metric SDK (`go.opentelemetry.io/otel/metric`) the
integration is the same shape — create instruments at startup, dispatch
on `e.Type`.
