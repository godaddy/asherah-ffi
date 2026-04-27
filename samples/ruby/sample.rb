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

# -- 4. Log + metrics hooks: forward observability events to your stack --
require "logger"
log_events = 0
metric_events = 0
# The simplest way: hand Asherah a Ruby Logger and let it dispatch via
# Logger#add(severity, message, target). Any Logger-compatible object works
# (ActiveSupport::Logger, SemanticLogger, Ougai, etc.).
#
#   stdout_logger = Logger.new($stdout)
#   stdout_logger.level = Logger::WARN
#   Asherah.set_log_hook(stdout_logger)
#
# Or pass a block to read each record's structured fields directly:
Asherah.set_log_hook do |event|
  log_events += 1
  # event[:severity] is a Logger::Severity integer (Logger::DEBUG ... ERROR);
  # event[:level] is the matching lowercase symbol.
  if event[:severity] >= Logger::INFO
    puts "[asherah-log #{event[:level]}] #{event[:target]}: #{event[:message]}"
  end
end
Asherah.set_metrics_hook do |event|
  metric_events += 1
  # In real code, dispatch to your metrics library (statsd, prometheus, etc.).
  # Timing events have non-zero duration_ns and nil name.
  # Cache events have non-nil name and duration_ns == 0.
end
Asherah.setup(CONFIG)
begin
  5.times do |i|
    ct = Asherah.encrypt_string("hooks-partition", "hook-payload-#{i}")
    Asherah.decrypt_string("hooks-partition", ct)
  end
ensure
  Asherah.shutdown
  Asherah.clear_log_hook
  Asherah.clear_metrics_hook
end
puts "Hooks observed #{log_events} log events and #{metric_events} metric events"

# -- 5. Production config (commented out) --
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
