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
end
