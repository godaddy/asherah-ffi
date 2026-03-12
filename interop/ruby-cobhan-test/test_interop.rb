#!/usr/bin/env ruby
# frozen_string_literal: true

# Interop test: canonical asherah-ruby gem backed by our Rust asherah-cobhan
#
# This test exercises the canonical godaddy/asherah-ruby gem's public API
# (configure, encrypt, decrypt, shutdown) but with our Rust cobhan shared
# library swapped in as a drop-in replacement for the Go cobhan library.

require 'asherah'
require 'json'
require 'securerandom'

PASS = 0
FAIL = 0
TESTS = []

def assert(description, &block)
  result = block.call
  if result
    TESTS << [:pass, description]
    puts "  PASS  #{description}"
  else
    TESTS << [:fail, description]
    puts "  FAIL  #{description}"
  end
rescue => e
  TESTS << [:fail, "#{description} (#{e.class}: #{e.message})"]
  puts "  FAIL  #{description} -- #{e.class}: #{e.message}"
end

def assert_equal(description, expected, actual)
  assert(description) { expected == actual }
  unless expected == actual
    puts "        expected: #{expected.inspect}"
    puts "          actual: #{actual.inspect}"
  end
end

def assert_raises(description, error_class, &block)
  begin
    block.call
    TESTS << [:fail, "#{description} (no exception raised)"]
    puts "  FAIL  #{description} -- no exception raised"
  rescue error_class
    TESTS << [:pass, description]
    puts "  PASS  #{description}"
  rescue => e
    TESTS << [:fail, "#{description} (wrong exception: #{e.class})"]
    puts "  FAIL  #{description} -- wrong exception: #{e.class}: #{e.message}"
  end
end

# ── Setup ────────────────────────────────────────────────────────────

puts
puts "=== Interop Test: canonical asherah-ruby + Rust asherah-cobhan ==="
puts

partition_id = 'interop-test-partition'

puts "--- Configure ---"
Asherah.configure do |config|
  config.service_name = 'interop-test-service'
  config.product_id = 'interop-test-product'
  config.kms = 'static'
  config.metastore = 'memory'
  config.enable_session_caching = true
  config.verbose = false
end
puts "  PASS  configure succeeded"

# ── Encrypt / Decrypt round-trips ────────────────────────────────────

puts
puts "--- Encrypt/Decrypt Round-trips ---"

# Simple ASCII string
plaintext = 'Hello from Ruby interop test!'
encrypted_json = Asherah.encrypt(partition_id, plaintext)
decrypted = Asherah.decrypt(partition_id, encrypted_json)
assert_equal('ASCII round-trip', plaintext, decrypted)

# Verify encrypted output is valid JSON with expected structure
parsed = JSON.parse(encrypted_json)
assert('encrypted output has Data field') { parsed.key?('Data') }
assert('encrypted output has Key field') { parsed.key?('Key') }
assert('Key has Created field') { parsed['Key'].key?('Created') }
assert('Key has Key field') { parsed['Key'].key?('Key') }
assert('Key has ParentKeyMeta') { parsed['Key'].key?('ParentKeyMeta') }

# UTF-8 multibyte string
utf8_text = "こんにちは世界 🌍 Ñoño"
encrypted_utf8 = Asherah.encrypt(partition_id, utf8_text)
decrypted_utf8 = Asherah.decrypt(partition_id, encrypted_utf8)
assert_equal('UTF-8 multibyte round-trip', utf8_text, decrypted_utf8)

# Empty string
encrypted_empty = Asherah.encrypt(partition_id, '')
decrypted_empty = Asherah.decrypt(partition_id, encrypted_empty)
assert_equal('empty string round-trip', '', decrypted_empty)

# Binary-like data with null bytes
binary_data = (0..255).map(&:chr).join
encrypted_binary = Asherah.encrypt(partition_id, binary_data)
decrypted_binary = Asherah.decrypt(partition_id, encrypted_binary)
assert_equal('binary data with null bytes round-trip (length)', binary_data.bytesize, decrypted_binary.bytesize)
assert_equal('binary data with null bytes round-trip (content)', binary_data.bytes, decrypted_binary.bytes)

# 1KB payload
data_1k = SecureRandom.random_bytes(1024)
encrypted_1k = Asherah.encrypt(partition_id, data_1k)
decrypted_1k = Asherah.decrypt(partition_id, encrypted_1k)
assert_equal('1KB payload round-trip', data_1k.bytes, decrypted_1k.bytes)

# 64KB payload
data_64k = SecureRandom.random_bytes(65536)
encrypted_64k = Asherah.encrypt(partition_id, data_64k)
decrypted_64k = Asherah.decrypt(partition_id, encrypted_64k)
assert_equal('64KB payload round-trip', data_64k.bytes, decrypted_64k.bytes)

# ── Cross-partition isolation ────────────────────────────────────────

puts
puts "--- Cross-partition Isolation ---"

encrypted_a = Asherah.encrypt('partition-a', 'secret-a')
encrypted_b = Asherah.encrypt('partition-b', 'secret-b')

decrypted_a = Asherah.decrypt('partition-a', encrypted_a)
decrypted_b = Asherah.decrypt('partition-b', encrypted_b)
assert_equal('partition-a decrypts correctly', 'secret-a', decrypted_a)
assert_equal('partition-b decrypts correctly', 'secret-b', decrypted_b)

# Decrypt with wrong partition should fail
begin
  Asherah.decrypt('partition-b', encrypted_a)
  # Some implementations may not fail on wrong partition (key ID mismatch
  # depends on whether suffix is enabled), so just note it
  puts "  INFO  cross-partition decrypt did not raise (may be expected)"
rescue => e
  puts "  PASS  cross-partition decrypt raised: #{e.class}"
end

# ── Multiple encryptions produce different ciphertexts ───────────────

puts
puts "--- Ciphertext Uniqueness ---"

enc1 = Asherah.encrypt(partition_id, 'same-data')
enc2 = Asherah.encrypt(partition_id, 'same-data')
assert('different ciphertexts for same plaintext') { enc1 != enc2 }

dec1 = Asherah.decrypt(partition_id, enc1)
dec2 = Asherah.decrypt(partition_id, enc2)
assert_equal('both decrypt to same plaintext', dec1, dec2)

# ── Shutdown ─────────────────────────────────────────────────────────

puts
puts "--- Shutdown ---"

Asherah.shutdown
puts "  PASS  shutdown succeeded"

# ── Summary ──────────────────────────────────────────────────────────

puts
pass_count = TESTS.count { |status, _| status == :pass }
fail_count = TESTS.count { |status, _| status == :fail }
total = TESTS.size

puts "=== Results: #{pass_count}/#{total} passed, #{fail_count} failed ==="

exit(fail_count > 0 ? 1 : 0)
