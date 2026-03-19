#!/usr/bin/env ruby
# frozen_string_literal: true

# Benchmark the canonical asherah Ruby gem (Cobhan/Go-based)
require "benchmark/ips"
require "asherah"

ENV["STATIC_MASTER_KEY_HEX"] ||= "22" * 32
mode = (ENV["BENCH_MODE"] || "memory").downcase
unless %w[memory hot warm cold].include?(mode)
  raise "Invalid BENCH_MODE=#{mode.inspect}; expected memory/hot/warm/cold"
end
partition_pool_size = Integer(ENV.fetch("BENCH_PARTITION_POOL", "2048"))
warm_session_cache_max = Integer(ENV.fetch("BENCH_WARM_SESSION_CACHE_MAX", "4096"))
raise "BENCH_PARTITION_POOL must be >= 1" if partition_pool_size < 1
raise "BENCH_WARM_SESSION_CACHE_MAX must be >= 1" if warm_session_cache_max < 1

Asherah.configure do |config|
  # Keep canonical benchmarks in a separate key namespace from FFI benchmarks
  # to avoid cross-implementation metastore key collisions.
  config.service_name = "bench-canon-svc"
  config.product_id = "bench-canon-prod"
  if mode == "hot"
    mysql_url = ENV["BENCH_MYSQL_URL"] || ENV["MYSQL_URL"]
    raise "hot mode requires BENCH_MYSQL_URL or MYSQL_URL" if mysql_url.nil? || mysql_url.empty?
    config.metastore = "rdbms"
    config.connection_string = mysql_url if config.respond_to?(:connection_string=)
  elsif mode == "warm"
    mysql_url = ENV["BENCH_MYSQL_URL"] || ENV["MYSQL_URL"]
    raise "warm mode requires BENCH_MYSQL_URL or MYSQL_URL" if mysql_url.nil? || mysql_url.empty?
    config.metastore = "rdbms"
    config.connection_string = mysql_url if config.respond_to?(:connection_string=)
    config.session_cache_max_size = warm_session_cache_max if config.respond_to?(:session_cache_max_size=)
  elsif mode == "cold"
    mysql_url = ENV["BENCH_MYSQL_URL"] || ENV["MYSQL_URL"]
    raise "cold mode requires BENCH_MYSQL_URL or MYSQL_URL" if mysql_url.nil? || mysql_url.empty?
    config.metastore = "rdbms"
    config.connection_string = mysql_url if config.respond_to?(:connection_string=)
    config.enable_session_caching = false if config.respond_to?(:enable_session_caching=)
  else
    config.metastore = "memory"
  end
  config.kms = "static"
  config.enable_session_caching = true unless mode == "cold"
end
mode_label = case mode
             when "memory" then "memory (in-memory hot-cache)"
             when "hot" then "hot (MySQL hot-cache)"
             when "warm" then "warm (MySQL, SK cached + IK miss)"
             else "cold (MySQL, SK-only cache)"
             end
puts "mode: #{mode_label}"

PARTITION = "bench-canon-partition"
SIZES = [64, 1024, 8192]

SIZES.each do |size|
  payload = Random.bytes(size)
  if mode == "cold"
    partitions = Array.new(partition_pool_size) { |i| "bench-canon-#{mode}-#{size}-#{i}" }
    ciphertexts = partitions.map { |partition| Asherah.encrypt(partition, payload) }
    recovered = Asherah.decrypt(partitions[0], ciphertexts[0])
    raise "Round-trip verification failed for #{size}B" unless recovered.b == payload.b
    enc_idx = 0
    dec_idx = 0
  else
    ct = Asherah.encrypt(PARTITION, payload)
    recovered = Asherah.decrypt(PARTITION, ct)
    raise "Round-trip verification failed for #{size}B" unless recovered.b == payload.b
  end

  puts "\n=== #{size}B payload ==="
  Benchmark.ips do |x|
    x.warmup = 2
    x.time = 5
    x.stats = :bootstrap
    x.confidence = 95

    if mode == "cold"
      x.report("encrypt #{size}B") do
        idx = enc_idx % partition_pool_size
        enc_idx += 1
        Asherah.encrypt(partitions[idx], payload)
      end
      x.report("decrypt #{size}B") do
        idx = dec_idx % partition_pool_size
        dec_idx += 1
        Asherah.decrypt(partitions[idx], ciphertexts[idx])
      end
    else
      x.report("encrypt #{size}B") { Asherah.encrypt(PARTITION, payload) }
      x.report("decrypt #{size}B") { Asherah.decrypt(PARTITION, ct) }
    end
  end
end

Asherah.shutdown
