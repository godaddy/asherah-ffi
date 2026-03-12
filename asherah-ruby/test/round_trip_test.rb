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
    assert_equal payload, recovered
  end

  def test_empty_payload
    payload = "".b
    json = Asherah.encrypt("ruby-empty", payload)
    recovered = Asherah.decrypt("ruby-empty", json)
    assert_equal payload, recovered
  end

  def test_large_payload_1mb
    payload = ((0..255).map(&:chr).join * 4096).b
    assert_equal 1_048_576, payload.bytesize
    json = Asherah.encrypt("ruby-large", payload)
    recovered = Asherah.decrypt("ruby-large", json)
    assert_equal payload.bytesize, recovered.bytesize
    assert_equal payload, recovered
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
end
