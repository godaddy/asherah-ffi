#!/usr/bin/env ruby
# frozen_string_literal: true

require "benchmark/ips"
require "asherah"

ENV["STATIC_MASTER_KEY_HEX"] ||= "746869734973415374617469634d61737465724b6579466f7254657374696e67"

cold = ENV["BENCH_COLD"] == "1"

bench_config = {
  "ServiceName" => "bench-svc",
  "ProductID" => "bench-prod",
  "Metastore" => ENV.fetch("BENCH_METASTORE", "memory"),
  "KMS" => "static",
  "EnableSessionCaching" => true
}
bench_config["ConnectionString"] = ENV["BENCH_CONNECTION_STRING"] if ENV["BENCH_CONNECTION_STRING"]
bench_config["CheckInterval"] = ENV["BENCH_CHECK_INTERVAL"].to_i if ENV["BENCH_CHECK_INTERVAL"]
bench_config["IntermediateKeyCacheMaxSize"] = 1 if cold
Asherah.setup(bench_config)

SIZES = [64, 1024, 8192]

SIZES.each do |size|
  payload = Random.bytes(size)

  if cold
    # Pre-encrypt on 2 partitions, alternate to force IK cache miss
    ct0 = Asherah.encrypt("cold-0", payload)
    ct1 = Asherah.encrypt("cold-1", payload)
    Asherah.decrypt("cold-0", ct0) # warm SK cache

    enc_ctr = 0
    dec_ctr = 0

    puts "\n=== #{size}B payload (cold) ==="
    Benchmark.ips do |x|
      x.warmup = 1
      x.time = 5
      x.stats = :bootstrap
      x.confidence = 95

      x.report("encrypt #{size}B") do
        enc_ctr += 1
        Asherah.encrypt("cold-enc-#{enc_ctr}", payload)
      end
      x.report("decrypt #{size}B") do
        i = dec_ctr % 2
        dec_ctr += 1
        Asherah.decrypt("cold-#{i}", i == 0 ? ct0 : ct1)
      end
    end
  else
    ct = Asherah.encrypt("bench-partition", payload)
    recovered = Asherah.decrypt("bench-partition", ct)
    raise "Round-trip verification failed for #{size}B" unless recovered == payload

    puts "\n=== #{size}B payload ==="
    Benchmark.ips do |x|
      x.warmup = 2
      x.time = 5
      x.stats = :bootstrap
      x.confidence = 95

      x.report("encrypt #{size}B") { Asherah.encrypt("bench-partition", payload) }
      x.report("decrypt #{size}B") { Asherah.decrypt("bench-partition", ct) }
    end
  end
end

Asherah.shutdown
