#!/usr/bin/env ruby
# frozen_string_literal: true

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

config = {
  "ServiceName" => "bench-svc",
  "ProductID" => "bench-prod",
  "KMS" => "static",
  "EnableSessionCaching" => true
}

if mode == "hot"
  mysql_url = ENV["BENCH_MYSQL_URL"] || ENV["MYSQL_URL"]
  raise "hot mode requires BENCH_MYSQL_URL or MYSQL_URL" if mysql_url.nil? || mysql_url.empty?
  config["Metastore"] = "rdbms"
  config["ConnectionString"] = mysql_url
elsif mode == "warm"
  mysql_url = ENV["BENCH_MYSQL_URL"] || ENV["MYSQL_URL"]
  raise "warm mode requires BENCH_MYSQL_URL or MYSQL_URL" if mysql_url.nil? || mysql_url.empty?
  config["Metastore"] = "rdbms"
  config["ConnectionString"] = mysql_url
  config["SessionCacheMaxSize"] = warm_session_cache_max
elsif mode == "cold"
  mysql_url = ENV["BENCH_MYSQL_URL"] || ENV["MYSQL_URL"]
  raise "cold mode requires BENCH_MYSQL_URL or MYSQL_URL" if mysql_url.nil? || mysql_url.empty?
  config["Metastore"] = "rdbms"
  config["ConnectionString"] = mysql_url
  config["EnableSessionCaching"] = false
else
  config["Metastore"] = "memory"
end

mode_label = case mode
             when "memory" then "memory (in-memory hot-cache)"
             when "hot" then "hot (MySQL hot-cache)"
             when "warm" then "warm (MySQL, SK cached + IK miss)"
             else "cold (MySQL, SK-only cache)"
             end
puts "mode: #{mode_label}"
Asherah.setup(config)

PARTITION = "bench-partition"
SIZES = [64, 1024, 8192]

SIZES.each do |size|
  payload = Random.bytes(size)
  if mode == "warm" || mode == "cold"
    partitions = Array.new(partition_pool_size) { |i| "bench-#{mode}-#{size}-#{i}" }
    ciphertexts = partitions.map { |partition| Asherah.encrypt(partition, payload) }
    recovered = Asherah.decrypt(partitions[0], ciphertexts[0])
    raise "Round-trip verification failed for #{size}B" unless recovered == payload
    enc_idx = 0
    dec_idx = 0
  else
    ct = Asherah.encrypt(PARTITION, payload)
    recovered = Asherah.decrypt(PARTITION, ct)
    raise "Round-trip verification failed for #{size}B" unless recovered == payload
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
