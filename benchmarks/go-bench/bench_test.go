package gobench

import (
	"bytes"
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	asherah "github.com/godaddy/asherah-go"
)

var sizes = []int{64, 1024, 8192}

func boolPtr(b bool) *bool { return &b }

const (
	partitionPoolSize    = 2048
	warmSessionCacheSize = 4096
)

var benchmarkMode string

var (
	flagMemory   = flag.Bool("memory", false, "use in-memory metastore hot-cache benchmark mode")
	flagHot      = flag.Bool("hot", false, "use MySQL hot-cache benchmark mode")
	flagWarm     = flag.Bool("warm", false, "use MySQL warm-cache benchmark mode (SK cached, IK miss path)")
	flagCold     = flag.Bool("cold", false, "use MySQL cold-cache benchmark mode (SK only cached)")
	flagMysqlURL = flag.String("mysql-url", "", "MySQL DSN/URL for --hot/--warm/--cold mode (or use BENCH_MYSQL_URL/MYSQL_URL)")
)

func resolveMode() (string, string, error) {
	selected := 0
	if *flagMemory {
		selected++
	}
	if *flagHot {
		selected++
	}
	if *flagWarm {
		selected++
	}
	if *flagCold {
		selected++
	}
	if selected > 1 {
		return "", "", fmt.Errorf("only one of --memory, --hot, --warm, or --cold may be set")
	}

	mode := os.Getenv("BENCH_MODE")
	if mode == "" {
		mode = "memory"
	}
	if *flagMemory {
		mode = "memory"
	}
	if *flagHot {
		mode = "hot"
	}
	if *flagWarm {
		mode = "warm"
	}
	if *flagCold {
		mode = "cold"
	}
	mode = strings.ToLower(mode)

	switch mode {
	case "memory":
		return mode, "", nil
	case "hot", "warm", "cold":
		url := *flagMysqlURL
		if url == "" {
			url = os.Getenv("BENCH_MYSQL_URL")
		}
		if url == "" {
			url = os.Getenv("MYSQL_URL")
		}
		if url == "" {
			return "", "", fmt.Errorf("%s mode requires MySQL URL via --mysql-url, BENCH_MYSQL_URL, or MYSQL_URL", mode)
		}
		return mode, url, nil
	default:
		return "", "", fmt.Errorf("invalid benchmark mode %q (expected memory, hot, warm, or cold)", mode)
	}
}

func buildPartitions(tag string, size int) []string {
	partitions := make([]string, partitionPoolSize)
	for i := range partitions {
		partitions[i] = fmt.Sprintf("bench-%s-%s-%d-%d", benchmarkMode, tag, size, i)
	}
	return partitions
}

func encryptNonEmpty(partition string, payload []byte) ([]byte, error) {
	for i := 0; i < 20; i++ {
		ct, err := asherah.Encrypt(partition, payload)
		if err != nil {
			return nil, err
		}
		if len(ct) > 0 {
			return ct, nil
		}
		time.Sleep(2 * time.Millisecond)
	}
	return nil, fmt.Errorf("encrypt returned empty ciphertext after retries")
}

func TestMain(m *testing.M) {
	flag.Parse()

	mode, mysqlURL, err := resolveMode()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Benchmark mode error: %v\n", err)
		os.Exit(2)
	}

	os.Setenv("STATIC_MASTER_KEY_HEX", "2222222222222222222222222222222222222222222222222222222222222222")

	enableSessionCaching := true
	cfg := asherah.Config{
		ServiceName: "bench-svc",
		ProductID:   "bench-prod",
		KMS:         "static",
	}
	switch mode {
	case "hot":
		cfg.Metastore = "rdbms"
		cfg.ConnectionString = &mysqlURL
		fmt.Fprintf(os.Stderr, "go-bench mode: hot (MySQL)\n")
	case "warm":
		cacheSize := warmSessionCacheSize
		cfg.Metastore = "rdbms"
		cfg.ConnectionString = &mysqlURL
		cfg.SessionCacheMaxSize = &cacheSize
		fmt.Fprintf(os.Stderr, "go-bench mode: warm (MySQL, SK cached + IK miss)\n")
	case "cold":
		enableSessionCaching = false
		cfg.Metastore = "rdbms"
		cfg.ConnectionString = &mysqlURL
		fmt.Fprintf(os.Stderr, "go-bench mode: cold (MySQL, SK-only cache)\n")
	default:
		cfg.Metastore = "memory"
		fmt.Fprintf(os.Stderr, "go-bench mode: memory\n")
	}
	cfg.EnableSessionCaching = boolPtr(enableSessionCaching)

	benchmarkMode = mode
	if err := asherah.Setup(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Setup failed: %v\n", err)
		os.Exit(1)
	}

	// Verify round-trip correctness for each payload size
	for _, size := range sizes {
		payload := make([]byte, size)
		rand.Read(payload)
		ct, err := encryptNonEmpty("bench-partition", payload)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Encrypt failed for %dB: %v\n", size, err)
			os.Exit(1)
		}
		pt, err := asherah.Decrypt("bench-partition", ct)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Decrypt failed for %dB: %v\n", size, err)
			os.Exit(1)
		}
		if !bytes.Equal(payload, pt) {
			fmt.Fprintf(os.Stderr, "Round-trip verification failed for %dB\n", size)
			os.Exit(1)
		}
	}

	code := m.Run()
	asherah.Shutdown()
	os.Exit(code)
}

func BenchmarkEncrypt(b *testing.B) {
	for _, size := range sizes {
		payload := make([]byte, size)
		rand.Read(payload)

		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			b.ReportAllocs()
			partitions := []string{"bench-partition"}
			if benchmarkMode == "warm" || benchmarkMode == "cold" {
				partitions = buildPartitions("enc", size)
				// Pre-encrypt so IKs exist in MySQL; benchmark measures
				// cache-miss load_latest, not IK creation.
				for _, p := range partitions {
					if _, err := encryptNonEmpty(p, payload); err != nil {
						b.Fatal(err)
					}
				}
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				partition := partitions[i%len(partitions)]
				ct, err := asherah.Encrypt(partition, payload)
				if err != nil {
					b.Fatal(err)
				}
				_ = ct
			}
		})
	}
}

func BenchmarkDecrypt(b *testing.B) {
	for _, size := range sizes {
		payload := make([]byte, size)
		rand.Read(payload)
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			b.ReportAllocs()
			partitions := []string{"bench-partition"}
			cts := make([][]byte, 1)

			if benchmarkMode == "warm" || benchmarkMode == "cold" {
				partitions = buildPartitions("dec", size)
				cts = make([][]byte, len(partitions))
				for i, partition := range partitions {
					ct, err := encryptNonEmpty(partition, payload)
					if err != nil {
						b.Fatal(err)
					}
					cts[i] = ct
				}
				if _, err := asherah.Decrypt(partitions[0], cts[0]); err != nil {
					b.Fatal(err)
				}
			} else {
				ct, err := encryptNonEmpty("bench-partition", payload)
				if err != nil {
					b.Fatal(err)
				}
				cts[0] = ct
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				idx := i % len(partitions)
				pt, err := asherah.Decrypt(partitions[idx], cts[idx])
				if err != nil {
					b.Fatal(err)
				}
				_ = pt
			}
		})
	}
}
