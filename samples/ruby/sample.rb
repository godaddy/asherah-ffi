# frozen_string_literal: true

# Memory metastore + static KMS — testing only.
# See production config at the bottom of this file.
ENV["STATIC_MASTER_KEY_HEX"] = "22" * 32

require "asherah"

CONFIG = {
  "ServiceName" => "sample-service",
  "ProductID" => "sample-product",
  "Metastore" => "memory",
  "KMS" => "static",                # testing only — use "aws" in production
  "EnableSessionCaching" => true
}.freeze

# -- 1. Static API: setup / encrypt_string / decrypt_string / shutdown --
Asherah.setup(CONFIG)
begin
  ciphertext = Asherah.encrypt_string("sample-partition", "Hello, static API!")
  puts "Static encrypt OK: #{ciphertext[0, 60]}..."

  recovered = Asherah.decrypt_string("sample-partition", ciphertext)
  puts "Static decrypt OK: #{recovered}"
ensure
  Asherah.shutdown
end

# -- 2. Session API: SessionFactory / get_session / encrypt_bytes / decrypt_bytes --
factory = Asherah::SessionFactory.new(
  Asherah::Native.asherah_factory_new_with_config(JSON.generate(CONFIG))
)
begin
  session = factory.get_session("sample-partition")
  begin
    encrypted = session.encrypt_bytes("Hello, session API!")
    puts "Session encrypt OK: #{encrypted.bytesize} bytes"

    decrypted = session.decrypt_bytes(encrypted)
    puts "Session decrypt OK: #{decrypted.force_encoding('UTF-8')}"
  ensure
    session.close
  end
ensure
  factory.close
end

# -- 3. Async API: encrypt_bytes_async / decrypt_bytes_async --
factory = Asherah::SessionFactory.new(
  Asherah::Native.asherah_factory_new_with_config(JSON.generate(CONFIG))
)
begin
  session = factory.get_session("sample-partition")
  begin
    encrypted = session.encrypt_bytes_async("Hello, async!")
    puts "Async encrypt OK: #{encrypted.bytesize} bytes"

    decrypted = session.decrypt_bytes_async(encrypted)
    puts "Async decrypt OK: #{decrypted.force_encoding('UTF-8')}"
  ensure
    session.close
  end
ensure
  factory.close
end

# -- 4. Production config (commented out) --
# Asherah.setup(
#   "ServiceName" => "my-service",
#   "ProductID" => "my-product",
#   "Metastore" => "dynamodb",           # or "mysql", "postgres"
#   "KMS" => "aws",
#   "RegionMap" => { "us-west-2" => "arn:aws:kms:us-west-2:..." },
#   "PreferredRegion" => "us-west-2",
#   "EnableRegionSuffix" => true,
#   "EnableSessionCaching" => true
# )
