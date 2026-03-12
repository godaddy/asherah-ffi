#!/usr/bin/env ruby
# frozen_string_literal: true

# Phase 1: Encrypt test vectors and write to file.
# Which cobhan library (Go or Rust) is active depends on which .dylib/.so
# was placed at the expected path before launching this process.

require 'asherah'
require 'base64'
require 'json'

output_file = ARGV[0] or abort("Usage: #{$0} <output_file>")
label = ENV['IMPL_LABEL'] || 'unknown'

db_path = ENV['ASHERAH_SQLITE_PATH'] or abort("ASHERAH_SQLITE_PATH must be set")

Asherah.configure do |config|
  config.service_name = 'cross-lang-service'
  config.product_id = 'cross-lang-product'
  config.kms = 'static'
  config.metastore = 'rdbms'
  config.connection_string = "sqlite://#{db_path}"
  config.enable_session_caching = true
end

test_vectors = {
  'ascii'  => 'Hello cross-language test!'.dup.force_encoding('BINARY'),
  'utf8'   => "Ünïcödé 日本語 🔑".encode('UTF-8').dup.force_encoding('BINARY'),
  'empty'  => ''.dup.force_encoding('BINARY'),
  'binary' => (0..255).map(&:chr).join.force_encoding('BINARY'),
  '1kb'    => Random.urandom(1024),
  '8kb'    => Random.urandom(8192),
}

results = {}
test_vectors.each do |name, plaintext|
  encrypted = Asherah.encrypt('cross-lang-partition', plaintext)
  results[name] = {
    'plaintext_b64'  => Base64.strict_encode64(plaintext),
    'encrypted_json' => encrypted,
  }
end

Asherah.shutdown

File.write(output_file, JSON.pretty_generate({
  'implementation' => label,
  'vectors' => results,
}))

$stderr.puts "  #{label}: encrypted #{results.size} test vectors -> #{output_file}"
