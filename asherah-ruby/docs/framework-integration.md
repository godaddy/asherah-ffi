# Framework integration

How to wire Asherah into common Ruby frameworks. The pattern is
consistent: **build a `SessionFactory` (or call `Asherah.setup`) at
startup, use sessions per request/job with `begin`/`ensure`/`close`,
and shut down on graceful exit.**

## Rails

`config/initializers/asherah.rb` is the right place:

```ruby
# config/initializers/asherah.rb
require "asherah"
require "json"

Rails.application.config.after_initialize do
  config = {
    "ServiceName" => Rails.application.config.asherah_service_name,
    "ProductID" => Rails.application.config.asherah_product_id,
    "Metastore" => "dynamodb",
    "DynamoDBTableName" => "AsherahKeys",
    "DynamoDBRegion" => Rails.application.config.aws_region,
    "KMS" => "aws",
    "RegionMap" => Rails.application.config.asherah_region_map,
    "PreferredRegion" => Rails.application.config.aws_region,
    "EnableSessionCaching" => true
  }

  Rails.application.config.asherah_factory = Asherah::SessionFactory.new(
    Asherah::Native.asherah_factory_new_with_config(JSON.generate(config))
  )

  # Forward Asherah log records into Rails.logger.
  Asherah.set_log_hook(Rails.logger)
end

# Graceful shutdown via at_exit:
at_exit do
  factory = Rails.application.config.asherah_factory
  factory&.close
end
```

In your model or service:

```ruby
class User < ApplicationRecord
  def protected_secret=(plaintext)
    factory = Rails.application.config.asherah_factory
    session = factory.get_session(id.to_s)
    begin
      self.secret_envelope = session.encrypt_string(plaintext)
    ensure
      session.close
    end
  end

  def protected_secret
    return nil if secret_envelope.blank?
    factory = Rails.application.config.asherah_factory
    session = factory.get_session(id.to_s)
    begin
      session.decrypt_string(secret_envelope)
    ensure
      session.close
    end
  end
end
```

For per-request sessions, use ActionController callbacks:

```ruby
class ApplicationController < ActionController::Base
  before_action :open_asherah_session
  after_action :close_asherah_session

  private

  def open_asherah_session
    return unless current_tenant
    @asherah_session = Rails.application.config.asherah_factory.get_session(current_tenant.id.to_s)
  end

  def close_asherah_session
    @asherah_session&.close
  end
end
```

The factory's session cache means the same session instance is
returned for the same tenant across requests until LRU-evicted —
`close` returns it to the cache, not destroys it.

## Sidekiq workers

```ruby
# config/initializers/asherah.rb (continued)
Sidekiq.configure_server do |config|
  config.on(:shutdown) do
    Rails.application.config.asherah_factory&.close
  end
end
```

```ruby
class ProtectPayloadWorker
  include Sidekiq::Job

  def perform(tenant_id, plaintext)
    factory = Rails.application.config.asherah_factory
    session = factory.get_session(tenant_id)
    begin
      ciphertext = session.encrypt_string(plaintext)
      EnvelopeStore.create!(tenant_id: tenant_id, envelope: ciphertext)
    ensure
      session.close
    end
  end
end
```

Sidekiq workers are threaded by default — Asherah's session cache and
factory are concurrency-safe, so multiple workers can share the
process-global factory without contention beyond the cache lookup.

## Sinatra

```ruby
require "sinatra"
require "asherah"
require "json"

config = {
  "ServiceName" => ENV["SERVICE_NAME"],
  "ProductID" => ENV["PRODUCT_ID"],
  # ...
}

set :asherah_factory, Asherah::SessionFactory.new(
  Asherah::Native.asherah_factory_new_with_config(JSON.generate(config))
)

at_exit { settings.asherah_factory.close }

post "/protect" do
  data = JSON.parse(request.body.read)
  session = settings.asherah_factory.get_session(data["tenant_id"])
  begin
    content_type :json
    { token: session.encrypt_string(data["plaintext"]) }.to_json
  ensure
    session.close
  end
end
```

## Rack middleware

```ruby
class AsherahSessionMiddleware
  def initialize(app, factory)
    @app = app
    @factory = factory
  end

  def call(env)
    tenant_id = env["HTTP_X_TENANT_ID"]
    if tenant_id
      env["asherah.session"] = @factory.get_session(tenant_id)
      begin
        @app.call(env)
      ensure
        env["asherah.session"].close
      end
    else
      @app.call(env)
    end
  end
end

# In config.ru:
# use AsherahSessionMiddleware, $asherah_factory
```

## AWS Lambda (with `aws-sam` Ruby runtime)

Build the factory at the top of the handler file so it survives
container reuse:

```ruby
require "asherah"
require "json"

# Module-level: built once per cold start, reused across warm invocations.
$factory ||= Asherah::SessionFactory.new(
  Asherah::Native.asherah_factory_new_with_config(JSON.generate({
    "ServiceName" => ENV["SERVICE_NAME"],
    "ProductID" => ENV["PRODUCT_ID"],
    "Metastore" => "dynamodb",
    "DynamoDBTableName" => ENV["ASHERAH_TABLE"],
    "DynamoDBRegion" => ENV["AWS_REGION"],
    "KMS" => "aws",
    "RegionMap" => JSON.parse(ENV["ASHERAH_REGION_MAP"]),
    "PreferredRegion" => ENV["AWS_REGION"]
  }))
)

def lambda_handler(event:, context:)
  session = $factory.get_session(event["tenantId"])
  begin
    {
      statusCode: 200,
      body: { token: session.encrypt_string(event["payload"]) }.to_json
    }
  ensure
    session.close
  end
end
```

Lambda doesn't reliably run shutdown hooks on container freeze — the
factory's resources are released when the Ruby process exits. No
explicit cleanup required.

## Logger integration

The simplest hook: hand Asherah a Logger-compatible object.

```ruby
require "logger"
log = Logger.new("log/asherah.log")
log.level = Logger::WARN
Asherah.set_log_hook(log)
```

Any object responding to `add(severity, message, target)` works —
including `ActiveSupport::Logger`, `SemanticLogger::Logger`, and
`Ougai::Logger`.

For Rails:

```ruby
Asherah.set_log_hook(Rails.logger)
```

Asherah's level-string ↔ `Logger::Severity` mapping is built in:
`trace`/`debug` → `Logger::DEBUG`, `info` → `Logger::INFO`, etc.

## StatsD / Prometheus metrics

```ruby
require "statsd-ruby"

statsd = Statsd.new("localhost", 8125)

Asherah.set_metrics_hook do |event|
  case event[:type]
  when :encrypt, :decrypt, :store, :load
    statsd.timing("asherah.#{event[:type]}", event[:duration_ns] / 1_000_000.0)
  when :cache_hit, :cache_miss, :cache_stale
    statsd.increment("asherah.cache.#{event[:type]}", tags: ["cache:#{event[:name]}"])
  end
end
```

For Prometheus's `prometheus-client` gem, the integration is the same
shape — create instruments at startup, increment in the block.
