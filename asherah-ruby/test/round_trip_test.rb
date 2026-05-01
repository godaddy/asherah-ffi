require_relative "test_helper"

class RoundTripTest < Minitest::Test
  def setup
    ENV["SERVICE_NAME"] = "svc"
    ENV["PRODUCT_ID"] = "prod"
    ENV["KMS"] = "static"
    ENV["STATIC_MASTER_KEY_HEX"] = "22" * 32
    ENV["Metastore"] = "memory"
    ENV["SESSION_CACHE"] = "0"
    config = {
      "ServiceName" => "svc",
      "ProductID" => "prod",
      "Metastore" => "memory",
      "KMS" => "static",
      "EnableSessionCaching" => true,
      "Verbose" => false
    }
    Asherah.setup(config)
  end

  def teardown
    Asherah.shutdown if Asherah.get_setup_status
  rescue Asherah::Error::NotInitialized
    # already shut down
  end

  def test_encrypts_and_decrypts_binary_payload
    plaintext = "ruby bindings secret".b
    json = Asherah.encrypt("partition", plaintext)
    refute_nil json
    assert_kind_of String, json
    recovered = Asherah.decrypt("partition", json)
    assert_equal plaintext, recovered
  end

  def test_can_setup_after_shutdown
    Asherah.shutdown
    refute Asherah.get_setup_status

    config = {
      "ServiceName" => "svc",
      "ProductID" => "prod",
      "Metastore" => "memory",
      "KMS" => "static",
      "EnableSessionCaching" => false,
      "Verbose" => false
    }

    Asherah.setup(config)
    begin
      json = Asherah.encrypt("repeat", "ruby-cycle")
      refute_nil json
      recovered = Asherah.decrypt("repeat", json)
      assert_equal "ruby-cycle", recovered.force_encoding("UTF-8")
    ensure
      Asherah.shutdown
    end

    refute Asherah.get_setup_status
  end

  # --- FFI Boundary Tests ---

  def test_unicode_cjk
    text = "你好世界こんにちは세계"
    json = Asherah.encrypt("ruby-unicode", text)
    recovered = Asherah.decrypt("ruby-unicode", json).force_encoding("UTF-8")
    assert_equal text, recovered
  end

  def test_unicode_emoji
    text = "🦀🔐🎉💾🌍"
    json = Asherah.encrypt("ruby-unicode", text)
    recovered = Asherah.decrypt("ruby-unicode", json).force_encoding("UTF-8")
    assert_equal text, recovered
  end

  def test_unicode_mixed_scripts
    text = "Hello 世界 مرحبا Привет 🌍"
    json = Asherah.encrypt("ruby-unicode", text)
    recovered = Asherah.decrypt("ruby-unicode", json).force_encoding("UTF-8")
    assert_equal text, recovered
  end

  def test_unicode_combining_characters
    text = "e\u0301 n\u0303 a\u0308"
    json = Asherah.encrypt("ruby-unicode", text)
    recovered = Asherah.decrypt("ruby-unicode", json).force_encoding("UTF-8")
    assert_equal text, recovered
  end

  def test_unicode_zwj_sequence
    text = "\u{1F468}\u200D\u{1F469}\u200D\u{1F467}\u200D\u{1F466}"
    json = Asherah.encrypt("ruby-unicode", text)
    recovered = Asherah.decrypt("ruby-unicode", json).force_encoding("UTF-8")
    assert_equal text, recovered
  end

  def test_binary_all_byte_values
    payload = (0..255).map(&:chr).join.b
    json = Asherah.encrypt("ruby-binary", payload)
    recovered = Asherah.decrypt("ruby-binary", json)
    assert_equal payload.bytes, recovered.bytes
  end

  def test_empty_payload
    payload = "".b
    json = Asherah.encrypt("ruby-empty", payload)
    recovered = Asherah.decrypt("ruby-empty", json)
    assert_equal payload.bytes, recovered.bytes
  end

  def test_large_payload_1mb
    payload = ((0..255).map(&:chr).join * 4096).b
    assert_equal 1_048_576, payload.bytesize
    json = Asherah.encrypt("ruby-large", payload)
    recovered = Asherah.decrypt("ruby-large", json)
    assert_equal payload.bytesize, recovered.bytesize
    assert_equal payload.bytes, recovered.bytes
  end

  def test_decrypt_invalid_json
    assert_raises(Asherah::Error) do
      Asherah.decrypt("ruby-error", "not valid json")
    end
  end

  def test_decrypt_wrong_partition
    json = Asherah.encrypt("partition-a", "secret".b)
    assert_raises(Asherah::Error) do
      Asherah.decrypt("partition-b", json)
    end
  end

  # ── Null and empty input handling ──
  #
  # Contract:
  #   - nil arguments are programming errors → ArgumentError raised by
  #     the binding before reaching native code.
  #   - empty String / empty bytes is a valid encrypt that round-trips
  #     back to empty.
  #   - decrypting an empty String is invalid JSON and must raise.

  def test_encrypt_nil_partition_raises
    assert_raises(ArgumentError) { Asherah.encrypt(nil, "x".b) }
  end

  def test_encrypt_nil_payload_raises
    assert_raises(ArgumentError) { Asherah.encrypt("p", nil) }
  end

  def test_encrypt_string_nil_text_raises
    assert_raises(ArgumentError) { Asherah.encrypt_string("p", nil) }
  end

  def test_decrypt_nil_partition_raises
    assert_raises(ArgumentError) { Asherah.decrypt(nil, "x") }
  end

  def test_decrypt_nil_data_raises
    assert_raises(ArgumentError) { Asherah.decrypt("p", nil) }
  end

  def test_decrypt_string_nil_data_raises
    assert_raises(ArgumentError) { Asherah.decrypt_string("p", nil) }
  end

  def test_empty_string_round_trip
    text = ""
    json = Asherah.encrypt_string("ruby-empty-str", text)
    refute_nil json
    assert json.length > 0
    recovered = Asherah.decrypt_string("ruby-empty-str", json).force_encoding("UTF-8")
    assert_equal text, recovered
  end

  def test_decrypt_empty_string_raises
    assert_raises(Asherah::Error) { Asherah.decrypt("ruby-empty-decrypt", "") }
    assert_raises(Asherah::Error) { Asherah.decrypt_string("ruby-empty-decrypt", "") }
  end
end

class FactorySessionTest < Minitest::Test
  CONFIG = {
    "ServiceName" => "svc",
    "ProductID" => "prod",
    "Metastore" => "memory",
    "KMS" => "static",
    "EnableSessionCaching" => true,
    "Verbose" => false
  }.freeze

  def make_factory
    pointer = Asherah::Native.asherah_factory_new_with_config(JSON.generate(CONFIG))
    Asherah::SessionFactory.new(pointer)
  end

  def test_factory_session_round_trip
    factory = make_factory
    begin
      session = factory.get_session("factory-rt")
      begin
        plaintext = "factory round trip secret".b
        json = session.encrypt_bytes(plaintext)
        refute_nil json
        assert_kind_of String, json
        recovered = session.decrypt_bytes(json)
        assert_equal plaintext, recovered
      ensure
        session.close
      end
      assert session.closed?
    ensure
      factory.close
    end
    assert factory.closed?
  end

  def test_factory_multiple_sessions_partition_isolation
    factory = make_factory
    begin
      session_a = factory.get_session("partition-iso-a")
      session_b = factory.get_session("partition-iso-b")
      begin
        json_a = session_a.encrypt_bytes("secret-a".b)
        json_b = session_b.encrypt_bytes("secret-b".b)

        # Each session decrypts its own data
        assert_equal "secret-a".b, session_a.decrypt_bytes(json_a)
        assert_equal "secret-b".b, session_b.decrypt_bytes(json_b)

        # Cross-partition decryption must fail
        assert_raises(Asherah::Error) { session_a.decrypt_bytes(json_b) }
        assert_raises(Asherah::Error) { session_b.decrypt_bytes(json_a) }
      ensure
        session_a.close
        session_b.close
      end
    ensure
      factory.close
    end
  end

  def test_factory_session_string_api
    factory = make_factory
    begin
      session = factory.get_session("factory-str")
      begin
        text = "hello from factory string api"
        json = session.encrypt_bytes(text)
        recovered = session.decrypt_bytes(json).force_encoding("UTF-8")
        assert_equal text, recovered
      ensure
        session.close
      end
    ensure
      factory.close
    end
  end

  def test_session_close_prevents_use
    factory = make_factory
    begin
      session = factory.get_session("close-test")
      session.encrypt_bytes("warmup".b)
      session.close
      assert session.closed?

      assert_raises(Asherah::Error) { session.encrypt_bytes("should fail".b) }
      assert_raises(Asherah::Error) { session.decrypt_bytes("{}") }
    ensure
      factory.close
    end
  end

  def test_concurrent_encrypt_decrypt
    factory = make_factory
    begin
      threads = 8.times.map do |i|
        Thread.new do
          session = factory.get_session("concurrent-#{i}")
          begin
            plaintext = "thread-#{i}-payload".b
            json = session.encrypt_bytes(plaintext)
            recovered = session.decrypt_bytes(json)
            assert_equal plaintext, recovered
          ensure
            session.close
          end
        end
      end
      threads.each(&:join)
    ensure
      factory.close
    end
  end

  def test_concurrent_same_partition_encrypt_decrypt
    factory = make_factory
    begin
      partition_id = "concurrent-shared"
      threads = 8.times.map do |i|
        Thread.new do
          session = factory.get_session(partition_id)
          begin
            plaintext = "shared-thread-#{i}-payload".b
            json = session.encrypt_bytes(plaintext)
            recovered = session.decrypt_bytes(json)
            assert_equal plaintext, recovered
          ensure
            session.close
          end
        end
      end
      threads.each(&:join)
    ensure
      factory.close
    end
  end

  def test_session_nil_args_raise
    factory = make_factory
    begin
      session = factory.get_session("session-nil")
      begin
        assert_raises(ArgumentError) { session.encrypt_bytes(nil) }
        assert_raises(ArgumentError) { session.decrypt_bytes(nil) }
      ensure
        session.close
      end
    ensure
      factory.close
    end
  end

  def test_session_empty_payload_round_trip
    factory = make_factory
    begin
      session = factory.get_session("session-empty")
      begin
        json = session.encrypt_bytes("".b)
        refute_nil json
        recovered = session.decrypt_bytes(json)
        assert_equal 0, recovered.bytesize
      ensure
        session.close
      end
    ensure
      factory.close
    end
  end

  def test_session_decrypt_empty_string_raises
    factory = make_factory
    begin
      session = factory.get_session("session-empty-decrypt")
      begin
        assert_raises(Asherah::Error) { session.decrypt_bytes("") }
      ensure
        session.close
      end
    ensure
      factory.close
    end
  end
end

# Tests for canonical godaddy/asherah-ruby API compatibility
class CanonicalCompatTest < Minitest::Test
  def setup
    ENV["STATIC_MASTER_KEY_HEX"] = "22" * 32
  end

  def teardown
    Asherah.shutdown if Asherah.get_setup_status
  rescue Asherah::Error::NotInitialized
    # already shut down
  end

  def test_configure_block_api
    Asherah.configure do |config|
      config.service_name = "compat-svc"
      config.product_id = "compat-prod"
      config.kms = "static"
      config.metastore = "memory"
    end
    ct = Asherah.encrypt("compat-part", "block config works")
    pt = Asherah.decrypt("compat-part", ct)
    assert_equal "block config works", pt
  end

  def test_configure_with_session_caching
    Asherah.configure do |config|
      config.service_name = "cache-svc"
      config.product_id = "cache-prod"
      config.kms = "static"
      config.metastore = "memory"
      config.enable_session_caching = true
    end
    ct = Asherah.encrypt("cache-part", "cached")
    pt = Asherah.decrypt("cache-part", ct)
    assert_equal "cached", pt
  end

  def test_set_env_alias
    assert Asherah.respond_to?(:set_env), "set_env method should exist"
    Asherah.set_env("COMPAT_TEST_VAR" => "compat_value")
    assert_equal "compat_value", ENV["COMPAT_TEST_VAR"]
  ensure
    ENV.delete("COMPAT_TEST_VAR")
  end

  def test_error_class_hierarchy
    assert Asherah::Error < StandardError
    assert Asherah::Error::ConfigError < Asherah::Error
    assert Asherah::Error::NotInitialized < Asherah::Error
    assert Asherah::Error::AlreadyInitialized < Asherah::Error
    assert Asherah::Error::GetSessionFailed < Asherah::Error
    assert Asherah::Error::EncryptFailed < Asherah::Error
    assert Asherah::Error::DecryptFailed < Asherah::Error
    assert Asherah::Error::BadConfig < Asherah::Error
  end

  def test_config_class_to_h
    config = Asherah::Config.new
    config.service_name = "svc"
    config.product_id = "prod"
    config.kms = "static"
    config.metastore = "memory"
    config.verbose = true
    h = config.to_h
    assert_equal "svc", h[:ServiceName]
    assert_equal "prod", h[:ProductID]
    assert_equal "static", h[:KMS]
    assert_equal "memory", h[:Metastore]
    assert_equal true, h[:Verbose]
    refute h.key?(:ConnectionString) # nil values excluded
  end

  def test_config_aws_profile_name_maps_and_omitted_when_nil
    config = Asherah::Config.new
    config.service_name = "svc"
    config.product_id = "prod"
    config.kms = "static"
    config.metastore = "memory"
    config.aws_profile_name = "staging"
    h = config.to_h
    assert_equal "staging", h[:AwsProfileName]

    config.aws_profile_name = nil
    h_cleared = config.to_h
    refute h_cleared.key?(:AwsProfileName)
  end

  def test_config_dynamo_db_signing_region_maps_and_omitted_when_nil
    config = Asherah::Config.new
    config.service_name = "svc"
    config.product_id = "prod"
    config.kms = "static"
    config.metastore = "dynamodb"
    config.dynamo_db_region = "us-east-1"
    config.dynamo_db_signing_region = "us-west-2"
    h = config.to_h
    assert_equal "us-east-1", h[:DynamoDBRegion]
    assert_equal "us-west-2", h[:DynamoDBSigningRegion]

    config.dynamo_db_signing_region = nil
    h_cleared = config.to_h
    refute h_cleared.key?(:DynamoDBSigningRegion)
    assert_equal "us-east-1", h_cleared[:DynamoDBRegion]
  end

  def test_config_validate_raises_on_missing_fields
    config = Asherah::Config.new
    assert_raises(Asherah::Error::ConfigError) { config.validate! }
  end

  def test_config_to_json
    config = Asherah::Config.new
    config.service_name = "svc"
    config.product_id = "prod"
    config.kms = "static"
    config.metastore = "memory"
    json = config.to_json
    parsed = JSON.parse(json)
    assert_equal "svc", parsed["ServiceName"]
    assert_equal "memory", parsed["Metastore"]
  end
end

# --- Async tests (Session-level, tokio-backed) ---

class AsyncSessionTest < Minitest::Test
  CONFIG = {
    "ServiceName" => "svc",
    "ProductID" => "prod",
    "Metastore" => "memory",
    "KMS" => "static",
    "EnableSessionCaching" => true,
    "Verbose" => false
  }.freeze

  def make_factory
    pointer = Asherah::Native.asherah_factory_new_with_config(JSON.generate(CONFIG))
    Asherah::SessionFactory.new(pointer)
  end

  def test_async_encrypt_decrypt_roundtrip
    factory = make_factory
    begin
      session = factory.get_session("async-rt")
      begin
        plaintext = "async ruby secret".b
        json = session.encrypt_bytes_async(plaintext)
        refute_nil json
        recovered = session.decrypt_bytes_async(json)
        assert_equal plaintext, recovered
      ensure
        session.close
      end
    ensure
      factory.close
    end
  end

  def test_async_empty_payload
    factory = make_factory
    begin
      session = factory.get_session("async-empty")
      begin
        json = session.encrypt_bytes_async("".b)
        recovered = session.decrypt_bytes_async(json)
        assert_equal "".b.bytes, recovered.bytes
      ensure
        session.close
      end
    ensure
      factory.close
    end
  end

  def test_async_concurrent
    factory = make_factory
    begin
      threads = 8.times.map do |i|
        Thread.new do
          session = factory.get_session("async-concurrent-#{i}")
          begin
            plaintext = "async-thread-#{i}".b
            json = session.encrypt_bytes_async(plaintext)
            recovered = session.decrypt_bytes_async(json)
            assert_equal plaintext, recovered
          ensure
            session.close
          end
        end
      end
      threads.each(&:join)
    ensure
      factory.close
    end
  end

  def test_async_nil_args_raise
    factory = make_factory
    begin
      session = factory.get_session("async-nil")
      begin
        assert_raises(ArgumentError) { session.encrypt_bytes_async(nil) }
        assert_raises(ArgumentError) { session.decrypt_bytes_async(nil) }
      ensure
        session.close
      end
    ensure
      factory.close
    end
  end
end
