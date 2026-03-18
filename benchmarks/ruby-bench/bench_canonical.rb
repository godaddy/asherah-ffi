#!/usr/bin/env ruby
# frozen_string_literal: true

# Benchmark the canonical asherah Ruby gem (Cobhan/Go-based)
require "benchmark/ips"
require "asherah"

ENV["STATIC_MASTER_KEY_HEX"] ||= "746869734973415374617469634d61737465724b6579466f7254657374696e67"

Asherah.configure do |config|
  config.service_name = "bench-svc"
  config.product_id = "bench-prod"
  config.metastore = ENV.fetch("BENCH_METASTORE", "memory")
  config.kms = "static"
  config.enable_session_caching = true
  config.connection_string = ENV["BENCH_CONNECTION_STRING_GO"] if ENV["BENCH_CONNECTION_STRING_GO"]
end

PARTITION = "bench-partition"
SIZES = [64, 1024, 8192]

SIZES.each do |size|
  payload = Random.bytes(size)
  ct = Asherah.encrypt(PARTITION, payload)

  # Verify round-trip correctness
  recovered = Asherah.decrypt(PARTITION, ct)
  raise "Round-trip verification failed for #{size}B" unless recovered.b == payload.b

  puts "\n=== #{size}B payload ==="
  Benchmark.ips do |x|
    x.warmup = 2
    x.time = 5
    x.stats = :bootstrap
    x.confidence = 95

    x.report("encrypt #{size}B") { Asherah.encrypt(PARTITION, payload) }
    x.report("decrypt #{size}B") { Asherah.decrypt(PARTITION, ct) }
  end
end

Asherah.shutdown
