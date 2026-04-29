# Testing your application code

Strategies for unit and integration tests of code that uses Asherah.
None of these require AWS or a database — Asherah ships with an
in-memory metastore and a static master-key mode.

## In-memory + static-KMS RSpec fixture

```ruby
# spec/support/asherah.rb
require "asherah"
require "json"

RSpec.shared_context "with asherah factory", shared_context: :metadata do
  let(:asherah_config) do
    ENV["STATIC_MASTER_KEY_HEX"] = "22" * 32
    {
      "ServiceName" => "test-svc",
      "ProductID" => "test-prod",
      "Metastore" => "memory",
      "KMS" => "static"
    }
  end

  let(:asherah_factory) do
    Asherah::SessionFactory.new(
      Asherah::Native.asherah_factory_new_with_config(JSON.generate(asherah_config))
    )
  end

  after { asherah_factory.close }
end

RSpec.configure do |config|
  config.include_context "with asherah factory", asherah: true
end
```

```ruby
# spec/services/protector_spec.rb
require "rails_helper"

RSpec.describe Protector, asherah: true do
  it "round-trips through Asherah" do
    session = asherah_factory.get_session("tenant-A")
    begin
      ct = session.encrypt_string("4242 4242 4242 4242")
      expect(session.decrypt_string(ct)).to eq("4242 4242 4242 4242")
    ensure
      session.close
    end
  end
end
```

For Minitest:

```ruby
# test/test_helper.rb
require "asherah"
require "json"

module AsherahFixture
  def setup
    super
    ENV["STATIC_MASTER_KEY_HEX"] = "22" * 32
    @asherah_factory = Asherah::SessionFactory.new(
      Asherah::Native.asherah_factory_new_with_config(JSON.generate({
        "ServiceName" => "test-svc",
        "ProductID" => "test-prod",
        "Metastore" => "memory",
        "KMS" => "static"
      }))
    )
  end

  def teardown
    @asherah_factory&.close
    super
  end
end
```

```ruby
# test/services/protector_test.rb
class ProtectorTest < ActiveSupport::TestCase
  include AsherahFixture

  test "round-trips" do
    session = @asherah_factory.get_session("tenant-A")
    begin
      ct = session.encrypt_string("4242 4242 4242 4242")
      assert_equal "4242 4242 4242 4242", session.decrypt_string(ct)
    ensure
      session.close
    end
  end
end
```

## Mocking Asherah for unit tests

The cleanest pattern: build a thin wrapper around Asherah in your
application code, mock the wrapper in unit tests.

```ruby
# app/services/protector.rb
class Protector
  def initialize(factory:)
    @factory = factory
  end

  def protect(partition_id, plaintext)
    session = @factory.get_session(partition_id)
    begin
      session.encrypt_string(plaintext)
    ensure
      session.close
    end
  end

  def unprotect(partition_id, ciphertext)
    session = @factory.get_session(partition_id)
    begin
      session.decrypt_string(ciphertext)
    ensure
      session.close
    end
  end
end
```

```ruby
# spec/services/order_service_spec.rb
RSpec.describe OrderService do
  it "calls Protector#protect" do
    protector = instance_double(Protector, protect: "ct-token")
    orders = OrderService.new(protector: protector)

    orders.create(partition_id: "merchant-7", payload: "card data")

    expect(protector).to have_received(:protect).with("merchant-7", "card data")
  end
end
```

The integration test of `Protector` itself uses the real
`asherah_factory`; unit tests of consumers mock `Protector` directly.

## Asserting envelope shape

```ruby
require "json"

it "envelope has expected shape" do
  session = asherah_factory.get_session("partition-1")
  begin
    envelope = JSON.parse(session.encrypt_string("hello"))
    expect(envelope).to include("Key", "Data")
    expect(envelope["Key"]).to include("ParentKeyMeta", "Created")
  ensure
    session.close
  end
end
```

## Hook tests run serially

Hooks are process-global. Tests exercising them can't run in
parallel — set RSpec's `:order => :defined` for the hook subset and
disable parallelism for those:

```ruby
RSpec.describe "log hook", :asherah, :hooks do
  # tag :hooks tests, run them serially via parallel-rspec config
  it "fires on encrypt" do
    events = []
    Asherah.set_log_hook { |e| events << e }
    # ... exercise encrypt
    Asherah.clear_log_hook
    expect(events).not_to be_empty
  end
end
```

For Rails apps using `parallel_tests`, exclude hook specs from
parallel runs or run them in a single-process subset.

## Testing with the SQL metastore (Testcontainers)

Use the `testcontainers-ruby` gem:

```ruby
require "testcontainers/mysql"

RSpec.shared_context "with mysql asherah factory" do
  let(:mysql_container) { Testcontainers::MysqlContainer.new("mysql:8.0").start }

  let(:asherah_factory) do
    ENV["STATIC_MASTER_KEY_HEX"] = "22" * 32
    Asherah::SessionFactory.new(
      Asherah::Native.asherah_factory_new_with_config(JSON.generate({
        "ServiceName" => "test-svc",
        "ProductID" => "test-prod",
        "Metastore" => "rdbms",
        "ConnectionString" => mysql_container.connection_url,
        "SQLMetastoreDBType" => "mysql",
        "KMS" => "static"
      }))
    )
  end

  after do
    asherah_factory.close
    mysql_container.stop
  end
end
```

Asherah's RDBMS metastore creates the schema on first use; no
migration required.

## Determinism caveats

- **AES-GCM nonces are random per encrypt call.** Ciphertext is
  non-deterministic — `encrypt_string("x")` produces a different
  envelope on every call. Don't compare ciphertext bytes; round-trip
  through `decrypt_string` and compare plaintexts.
- **Session caching.** `factory.get_session("p")` returns a cached
  session by default. Tests asserting per-call behaviour should set
  `EnableSessionCaching: false`.
- **Hooks are process-global.** Run hook tests serially.
- **Static-master-key sharing across tests.** All tests in one
  process use the same `STATIC_MASTER_KEY_HEX` — envelopes encrypted
  in one test can be decrypted by another. If a test depends on
  isolation, set a different `STATIC_MASTER_KEY_HEX` in `before`
  AND call `Asherah.shutdown` so the static-KMS reload picks it up.

## Native library resolution in tests

Bundler picks the right platform gem at install. If `LoadError`s
appear at test time:

- `bundle lock --add-platform x86_64-linux-musl` (or your platform)
  to ensure the lockfile includes the prebuilt gem.
- `gem env` to confirm the right gem version was installed.
- For repo development: `bundle config local.asherah <path>` and
  `bundle install` to pick up your local checkout.
