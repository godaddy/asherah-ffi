#!/usr/bin/env ruby
# Benchmark: canonical asherah gem (Go cobhan binding)

require "asherah"

WARMUP = Integer(ENV.fetch("WARMUP", "1000"))
ITERATIONS = Integer(ENV.fetch("ITERATIONS", "10000"))
PAYLOAD = ENV.fetch("PAYLOAD", "the quick brown fox jumps over the lazy dog")
PARTITION = "bench-partition"

Asherah.configure do |config|
  config.service_name = "bench-svc"
  config.product_id = "bench-prod"
  config.metastore = "memory"
  config.kms = "static"
  config.enable_session_caching = true
end

# Warmup
WARMUP.times { |i|
  ct = Asherah.encrypt(PARTITION, PAYLOAD)
  Asherah.decrypt(PARTITION, ct)
}

# Benchmark encrypt
ct_sample = nil
t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
ITERATIONS.times {
  ct_sample = Asherah.encrypt(PARTITION, PAYLOAD)
}
t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
encrypt_elapsed = t1 - t0

# Benchmark decrypt
t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
ITERATIONS.times {
  Asherah.decrypt(PARTITION, ct_sample)
}
t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
decrypt_elapsed = t1 - t0

Asherah.shutdown

encrypt_ops = ITERATIONS / encrypt_elapsed
decrypt_ops = ITERATIONS / decrypt_elapsed

puts "impl=go-cobhan"
puts "iterations=#{ITERATIONS}"
puts "payload_size=#{PAYLOAD.bytesize}"
puts "encrypt_total=%.4f" % encrypt_elapsed
puts "decrypt_total=%.4f" % decrypt_elapsed
puts "encrypt_ops_sec=%.0f" % encrypt_ops
puts "decrypt_ops_sec=%.0f" % decrypt_ops
puts "encrypt_us_op=%.1f" % (encrypt_elapsed / ITERATIONS * 1_000_000)
puts "decrypt_us_op=%.1f" % (decrypt_elapsed / ITERATIONS * 1_000_000)
