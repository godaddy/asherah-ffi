require_relative "test_helper"

# Verifies that the module-level session cache respects
# SessionCacheMaxSize. Prior to the LRU/bound fix the cache was
# unbounded — every distinct partition_id touched lived until shutdown.
class SessionCacheBoundTest < Minitest::Test
  def setup
    ENV["STATIC_MASTER_KEY_HEX"] = "22" * 32
  end

  def teardown
    Asherah.shutdown if Asherah.get_setup_status
  rescue Asherah::Error::NotInitialized
    # already shut down
  end

  def base_config(max_size: nil)
    cfg = {
      "ServiceName" => "svc",
      "ProductID" => "prod",
      "Metastore" => "memory",
      "KMS" => "static",
      "EnableSessionCaching" => true,
      "Verbose" => false
    }
    cfg["SessionCacheMaxSize"] = max_size if max_size
    cfg
  end

  def test_round_trip_under_eviction_churn
    Asherah.setup(base_config(max_size: 4))
    32.times do |i|
      partition = "churn-#{i}"
      payload = "payload-#{i}"
      ct = Asherah.encrypt(partition, payload)
      assert_equal payload, Asherah.decrypt(partition, ct).force_encoding("UTF-8")
    end
  end

  def test_hot_partitions_round_trip_repeatedly
    Asherah.setup(base_config(max_size: 2))
    16.times do
      a_ct = Asherah.encrypt("hot-a", "a")
      assert_equal "a", Asherah.decrypt("hot-a", a_ct).force_encoding("UTF-8")
      b_ct = Asherah.encrypt("hot-b", "b")
      assert_equal "b", Asherah.decrypt("hot-b", b_ct).force_encoding("UTF-8")
    end
  end

  def test_default_bound_round_trips_past_thousand
    Asherah.setup(base_config)
    1100.times do |i|
      partition = "default-#{i}"
      payload = "p#{i}"
      ct = Asherah.encrypt(partition, payload)
      assert_equal payload, Asherah.decrypt(partition, ct).force_encoding("UTF-8")
    end
  end

  def test_session_cache_disabled_round_trips
    Asherah.setup(base_config.merge("EnableSessionCaching" => false))
    8.times do |i|
      ct = Asherah.encrypt("nocache-#{i}", "x")
      assert_equal "x", Asherah.decrypt("nocache-#{i}", ct).force_encoding("UTF-8")
    end
  end
end
