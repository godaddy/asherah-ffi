#!/usr/bin/env ruby

require "base64"

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))
require "asherah"

def usage!
  warn "Usage: interop.rb <encrypt|decrypt> <partition> <base64>"
  exit 1
end

usage! if ARGV.length < 3

action = ARGV[0]
partition = ARGV[1]
payload = ARGV[2]

config = {
  "ServiceName" => ENV.fetch("SERVICE_NAME", "service"),
  "ProductID" => ENV.fetch("PRODUCT_ID", "product"),
  "Metastore" => ENV.fetch("Metastore", "memory"),
  "KMS" => ENV.fetch("KMS", "static"),
  "EnableSessionCaching" => ENV.fetch("SESSION_CACHE", "1") != "0",
  "Verbose" => false
}

if ENV.key?("CONNECTION_STRING")
  config["ConnectionString"] = ENV["CONNECTION_STRING"]
elsif ENV.key?("SQLITE_PATH")
  config["ConnectionString"] = ENV["SQLITE_PATH"]
end

Asherah.setup(config)
begin
  case action
  when "encrypt"
    data = Base64.strict_decode64(payload)
    json = Asherah.encrypt(partition, data)
    print Base64.strict_encode64(json)
  when "decrypt"
    json = Base64.strict_decode64(payload).force_encoding(Encoding::UTF_8)
    recovered = Asherah.decrypt(partition, json)
    print Base64.strict_encode64(recovered)
  else
    usage!
  end
ensure
  Asherah.shutdown
end
