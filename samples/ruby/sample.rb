# A static master key for local development only.
# In production, use KMS: "aws" with a proper region map.
ENV["STATIC_MASTER_KEY_HEX"] = "22" * 32

require "asherah"

Asherah.setup(
  "ServiceName" => "sample-service",
  "ProductID" => "sample-product",
  "Metastore" => "memory",
  "KMS" => "static",
  "EnableSessionCaching" => true
)

# Encrypt
ciphertext = Asherah.encrypt_string("sample-partition", "Hello from Ruby!")
puts "Encrypted: #{ciphertext[0, 80]}..."

# Decrypt
recovered = Asherah.decrypt_string("sample-partition", ciphertext)
puts "Decrypted: #{recovered}"

Asherah.shutdown
