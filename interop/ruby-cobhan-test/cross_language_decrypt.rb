#!/usr/bin/env ruby
# frozen_string_literal: true

# Phase 2: Read encrypted test vectors and decrypt them.
# Verifies that ciphertext produced by one implementation can be decrypted
# by whichever implementation is currently loaded.

require 'asherah'
require 'base64'
require 'json'

input_file = ARGV[0] or abort("Usage: #{$0} <input_file>")
label = ENV['IMPL_LABEL'] || 'unknown'

data = JSON.parse(File.read(input_file))
source_impl = data['implementation']
vectors = data['vectors']

db_path = ENV['ASHERAH_SQLITE_PATH'] or abort("ASHERAH_SQLITE_PATH must be set")

Asherah.configure do |config|
  config.service_name = 'cross-lang-service'
  config.product_id = 'cross-lang-product'
  config.kms = 'static'
  config.metastore = 'rdbms'
  config.connection_string = "sqlite://#{db_path}"
  config.enable_session_caching = true
end

pass = 0
fail = 0

vectors.each do |name, vec|
  expected_plaintext = Base64.strict_decode64(vec['plaintext_b64'])
  encrypted_json = vec['encrypted_json']

  begin
    decrypted = Asherah.decrypt('cross-lang-partition', encrypted_json)
    # Force binary encoding for byte-level comparison
    decrypted.force_encoding('BINARY')

    if decrypted == expected_plaintext
      puts "  PASS  #{source_impl} -> #{label}: #{name}"
      pass += 1
    else
      puts "  FAIL  #{source_impl} -> #{label}: #{name} (content mismatch)"
      puts "        expected #{expected_plaintext.bytesize} bytes, got #{decrypted.bytesize} bytes"
      fail += 1
    end
  rescue => e
    puts "  FAIL  #{source_impl} -> #{label}: #{name} (#{e.class}: #{e.message})"
    fail += 1
  end
end

Asherah.shutdown

puts
puts "  #{source_impl} -> #{label}: #{pass}/#{pass + fail} passed"
exit(fail > 0 ? 1 : 0)
