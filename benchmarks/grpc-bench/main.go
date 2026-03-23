package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "grpc-bench/api"
)

func main() {
	socketPath := flag.String("socket", "/tmp/appencryption.sock", "Unix socket path")
	iterations := flag.Int("n", 10000, "Number of encrypt+decrypt iterations")
	warmup := flag.Int("warmup", 1000, "Number of warmup iterations")
	payloadSize := flag.Int("payload", 43, "Payload size in bytes")
	streams := flag.Int("streams", 1, "Number of concurrent streams")
	server := flag.String("server", "", "Server binary to auto-start (optional)")
	serverArgs := flag.String("server-args", "", "Additional server args (comma-separated)")
	flag.Parse()

	// Auto-start server if requested
	var cmd *exec.Cmd
	if *server != "" {
		args := []string{
			"--service", "bench-svc",
			"--product", "bench-prod",
			"--metastore", "memory",
			"--kms", "static",
			"--enable-session-caching",
			"--socket-file", *socketPath,
		}
		if *serverArgs != "" {
			for _, a := range strings.Split(*serverArgs, ",") {
				a = strings.TrimSpace(a)
				if a != "" {
					args = append(args, a)
				}
			}
		}
		cmd = exec.Command(*server, args...)
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			log.Fatalf("failed to start server: %v", err)
		}
		defer func() {
			cmd.Process.Signal(os.Interrupt)
			cmd.Wait()
			os.Remove(*socketPath)
		}()
		// Wait for socket to appear
		for i := 0; i < 50; i++ {
			if _, err := os.Stat(*socketPath); err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Connect
	conn, err := grpc.NewClient(
		"unix://"+*socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatalf("failed to connect: %v", err)
	}
	defer conn.Close()

	client := pb.NewAppEncryptionClient(conn)
	payload := make([]byte, *payloadSize)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	if *streams == 1 {
		benchSingle(client, payload, *warmup, *iterations)
	} else {
		benchConcurrent(client, payload, *warmup, *iterations, *streams)
	}
}

func benchSingle(client pb.AppEncryptionClient, payload []byte, warmup, iterations int) {
	ctx := context.Background()
	stream, err := client.Session(ctx)
	if err != nil {
		log.Fatalf("failed to open session stream: %v", err)
	}

	// Send GetSession and consume the empty ack response
	err = stream.Send(&pb.SessionRequest{
		Request: &pb.SessionRequest_GetSession{
			GetSession: &pb.GetSession{PartitionId: "bench-partition"},
		},
	})
	if err != nil {
		log.Fatalf("failed to send GetSession: %v", err)
	}
	if _, err = stream.Recv(); err != nil {
		log.Fatalf("failed to recv GetSession ack: %v", err)
	}

	// Warmup
	for i := 0; i < warmup; i++ {
		drr := doEncrypt(stream, payload)
		doDecrypt(stream, drr)
	}

	// Benchmark encrypt
	var encryptedSample *pb.DataRowRecord
	t0 := time.Now()
	for i := 0; i < iterations; i++ {
		encryptedSample = doEncrypt(stream, payload)
	}
	encryptElapsed := time.Since(t0)

	// Benchmark decrypt
	t0 = time.Now()
	for i := 0; i < iterations; i++ {
		doDecrypt(stream, encryptedSample)
	}
	decryptElapsed := time.Since(t0)

	stream.CloseSend()

	printResults("single-stream", len(payload), iterations, encryptElapsed, decryptElapsed)
}

func benchConcurrent(client pb.AppEncryptionClient, payload []byte, warmup, iterations, numStreams int) {
	perStream := iterations / numStreams

	var (
		mu              sync.Mutex
		totalEncrypt    time.Duration
		totalDecrypt    time.Duration
		totalIterations int
	)

	var wg sync.WaitGroup
	wg.Add(numStreams)

	t0 := time.Now()
	for s := 0; s < numStreams; s++ {
		go func(streamIdx int) {
			defer wg.Done()
			ctx := context.Background()
			stream, err := client.Session(ctx)
			if err != nil {
				log.Printf("stream %d: failed to open: %v", streamIdx, err)
				return
			}

			partitionID := fmt.Sprintf("bench-partition-%d", streamIdx)
			err = stream.Send(&pb.SessionRequest{
				Request: &pb.SessionRequest_GetSession{
					GetSession: &pb.GetSession{PartitionId: partitionID},
				},
			})
			if err != nil {
				log.Printf("stream %d: GetSession failed: %v", streamIdx, err)
				return
			}
			if _, err = stream.Recv(); err != nil {
				log.Printf("stream %d: GetSession ack failed: %v", streamIdx, err)
				return
			}

			// Warmup
			for i := 0; i < warmup/numStreams; i++ {
				drr := doEncrypt(stream, payload)
				doDecrypt(stream, drr)
			}

			// Encrypt
			var sample *pb.DataRowRecord
			eStart := time.Now()
			for i := 0; i < perStream; i++ {
				sample = doEncrypt(stream, payload)
			}
			eElapsed := time.Since(eStart)

			// Decrypt
			dStart := time.Now()
			for i := 0; i < perStream; i++ {
				doDecrypt(stream, sample)
			}
			dElapsed := time.Since(dStart)

			stream.CloseSend()

			mu.Lock()
			totalEncrypt += eElapsed
			totalDecrypt += dElapsed
			totalIterations += perStream
			mu.Unlock()
		}(s)
	}
	wg.Wait()
	wallTime := time.Since(t0)

	// Report aggregate throughput based on wall time
	totalOps := numStreams * perStream
	encryptOpsPerSec := float64(totalOps) / wallTime.Seconds()
	// For per-stream latency, use average
	avgEncryptPerOp := totalEncrypt / time.Duration(totalIterations)
	avgDecryptPerOp := totalDecrypt / time.Duration(totalIterations)

	fmt.Printf("streams=%d\n", numStreams)
	fmt.Printf("iterations=%d (total)\n", totalOps)
	fmt.Printf("payload_size=%d\n", len(payload))
	fmt.Printf("wall_time=%.4f\n", wallTime.Seconds())
	fmt.Printf("encrypt_throughput_ops_sec=%.0f\n", encryptOpsPerSec)
	fmt.Printf("decrypt_throughput_ops_sec=%.0f\n", float64(totalOps)/wallTime.Seconds())
	fmt.Printf("avg_encrypt_us_op=%.1f\n", float64(avgEncryptPerOp.Microseconds()))
	fmt.Printf("avg_decrypt_us_op=%.1f\n", float64(avgDecryptPerOp.Microseconds()))
}

func doEncrypt(stream pb.AppEncryption_SessionClient, data []byte) *pb.DataRowRecord {
	err := stream.Send(&pb.SessionRequest{
		Request: &pb.SessionRequest_Encrypt{
			Encrypt: &pb.Encrypt{Data: data},
		},
	})
	if err != nil {
		if err == io.EOF {
			log.Fatal("encrypt send: server closed stream")
		}
		log.Fatalf("encrypt send: %v", err)
	}

	resp, err := stream.Recv()
	if err != nil {
		log.Fatalf("encrypt recv: %v", err)
	}

	switch r := resp.Response.(type) {
	case *pb.SessionResponse_EncryptResponse:
		return r.EncryptResponse.DataRowRecord
	case *pb.SessionResponse_ErrorResponse:
		log.Fatalf("encrypt error: %s", r.ErrorResponse.Message)
	default:
		log.Fatalf("unexpected response type: %T", r)
	}
	return nil
}

func doDecrypt(stream pb.AppEncryption_SessionClient, drr *pb.DataRowRecord) []byte {
	err := stream.Send(&pb.SessionRequest{
		Request: &pb.SessionRequest_Decrypt{
			Decrypt: &pb.Decrypt{DataRowRecord: drr},
		},
	})
	if err != nil {
		if err == io.EOF {
			log.Fatal("decrypt send: server closed stream")
		}
		log.Fatalf("decrypt send: %v", err)
	}

	resp, err := stream.Recv()
	if err != nil {
		log.Fatalf("decrypt recv: %v", err)
	}

	switch r := resp.Response.(type) {
	case *pb.SessionResponse_DecryptResponse:
		return r.DecryptResponse.Data
	case *pb.SessionResponse_ErrorResponse:
		log.Fatalf("decrypt error: %s", r.ErrorResponse.Message)
	default:
		log.Fatalf("unexpected response type: %T", r)
	}
	return nil
}

func printResults(label string, payloadSize, iterations int, encryptElapsed, decryptElapsed time.Duration) {
	encryptOps := float64(iterations) / encryptElapsed.Seconds()
	decryptOps := float64(iterations) / decryptElapsed.Seconds()
	encryptUs := float64(encryptElapsed.Microseconds()) / float64(iterations)
	decryptUs := float64(decryptElapsed.Microseconds()) / float64(iterations)

	fmt.Printf("impl=%s\n", label)
	fmt.Printf("iterations=%d\n", iterations)
	fmt.Printf("payload_size=%d\n", payloadSize)
	fmt.Printf("encrypt_total=%.4f\n", encryptElapsed.Seconds())
	fmt.Printf("decrypt_total=%.4f\n", decryptElapsed.Seconds())
	fmt.Printf("encrypt_ops_sec=%.0f\n", encryptOps)
	fmt.Printf("decrypt_ops_sec=%.0f\n", decryptOps)
	fmt.Printf("encrypt_us_op=%.1f\n", encryptUs)
	fmt.Printf("decrypt_us_op=%.1f\n", decryptUs)

	_ = net.Dial // keep net import for unix socket
}
