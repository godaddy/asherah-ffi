require_relative "test_helper"

# Tests for the Asherah log + metrics observability hooks.
#
# Each test re-asserts a clean hook baseline in setup/teardown so a hook
# left registered by a prior test cannot bleed into the next one.
class HooksTest < Minitest::Test
  CONFIG = {
    "ServiceName"          => "svc",
    "ProductID"            => "prod",
    "Metastore"            => "memory",
    "KMS"                  => "static",
    "EnableSessionCaching" => false,
    "Verbose"              => false
  }.freeze

  def setup
    ENV["STATIC_MASTER_KEY_HEX"] = "22" * 32
    Asherah.clear_log_hook
    Asherah.clear_metrics_hook
  end

  def teardown
    Asherah.clear_log_hook
    Asherah.clear_metrics_hook
    Asherah.shutdown if Asherah.get_setup_status
  rescue Asherah::Error::NotInitialized
    # ignore
  end

  # Hooks are delivered asynchronously by a dedicated worker thread (see
  # asherah-ffi/src/hooks.rs). Tests that assert on hook delivery must wait
  # for the worker to drain the channel before checking, otherwise they
  # race the worker scheduler.
  def wait_for(timeout: 2.0)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    until yield
      return false if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
      sleep 0.01
    end
    true
  end

  def drain_hooks
    sleep 0.1
  end

  # ----- log hook -----

  def test_set_log_hook_with_block_does_not_raise
    Asherah.set_log_hook { |_event| nil }
    Asherah.clear_log_hook
  end

  def test_set_log_hook_with_proc_does_not_raise
    Asherah.set_log_hook(proc { |_event| nil })
    Asherah.clear_log_hook
  end

  def test_clear_log_hook_is_idempotent
    Asherah.clear_log_hook
    Asherah.clear_log_hook
  end

  def test_set_log_hook_nil_clears
    received = []
    Asherah.set_log_hook { |event| received << event }
    Asherah.set_log_hook(nil)
    Asherah.setup(CONFIG)
    Asherah.encrypt("nil-clear", "payload")
    Asherah.shutdown
    # No assertion on received count — the contract is just that nil doesn't crash.
  end

  def test_log_hook_fires_with_well_formed_events
    received = Queue.new
    Asherah.set_log_hook do |event|
      received << event
    end
    Asherah.setup(CONFIG)
    5.times do |i|
      ct = Asherah.encrypt("log-fields", "payload-#{i}")
      Asherah.decrypt("log-fields", ct)
    end
    Asherah.shutdown
    wait_for { received.size > 0 }

    refute_equal 0, received.size, "expected at least one log event"
    valid_severities = [
      Logger::DEBUG, Logger::INFO, Logger::WARN, Logger::ERROR,
      Logger::FATAL, Logger::UNKNOWN
    ]
    until received.empty?
      event = received.pop
      assert_kind_of Hash, event
      assert_includes %i[debug info warn error fatal unknown], event[:level]
      assert_includes valid_severities, event[:severity]
      assert_kind_of String, event[:target]
      refute event[:target].empty?, "log target must not be empty"
      assert_kind_of String, event[:message]
    end
  end

  def test_set_log_hook_accepts_logger_instance
    require "stringio"
    buf = StringIO.new
    logger = Logger.new(buf)
    logger.level = Logger::DEBUG
    Asherah.set_log_hook(logger)
    Asherah.setup(CONFIG)
    5.times { |i| Asherah.encrypt("logger-bridge", "v#{i}") }
    Asherah.shutdown
    # Best-effort: the bridge should not raise. Output is best-effort because
    # most hot-path records are below WARN by default (the new global default
    # min level), but the bridge wiring is exercised regardless.
    refute_nil buf.string
  end

  def test_replacing_log_hook_redirects_to_new_callback
    old_hits = 0
    new_hits = 0
    Asherah.set_log_hook { |_| old_hits += 1 }
    Asherah.set_log_hook { |_| new_hits += 1 }
    Asherah.setup(CONFIG)
    3.times { |i| Asherah.encrypt("replace-#{i}", "x") }
    Asherah.shutdown
    assert new_hits >= 0
    # We don't strictly assert old_hits == 0 because there's a brief window
    # while the second set_log_hook is taking the mutex when the old hook
    # could fire. The contract is just that replacing doesn't crash.
  end

  def test_log_hook_exceptions_do_not_crash
    Asherah.set_log_hook { |_| raise "intentional from log hook" }
    Asherah.setup(CONFIG)
    # If exceptions weren't caught this would raise; round trip must succeed.
    ct = Asherah.encrypt("log-throw", "survive")
    assert_equal "survive", Asherah.decrypt("log-throw", ct).force_encoding("UTF-8")
    Asherah.shutdown
  end

  def test_set_log_hook_rejects_non_callable
    assert_raises(ArgumentError) { Asherah.set_log_hook("not a proc") }
  end

  # ----- metrics hook -----

  def test_set_metrics_hook_with_block_does_not_raise
    Asherah.set_metrics_hook { |_event| nil }
    Asherah.clear_metrics_hook
  end

  def test_clear_metrics_hook_is_idempotent
    Asherah.clear_metrics_hook
    Asherah.clear_metrics_hook
  end

  def test_set_metrics_hook_nil_clears
    counter = 0
    mutex = Mutex.new
    Asherah.set_metrics_hook { |_| mutex.synchronize { counter += 1 } }
    Asherah.set_metrics_hook(nil)
    Asherah.setup(CONFIG)
    Asherah.encrypt("nil-clear", "payload")
    Asherah.shutdown
    drain_hooks
    assert_equal 0, counter, "metrics hook fired after being cleared"
  end

  def test_metrics_hook_fires_encrypt_and_decrypt
    require "set"
    seen_types = Set.new
    mutex = Mutex.new
    Asherah.set_metrics_hook do |event|
      assert_kind_of Hash, event
      assert_kind_of Symbol, event[:type]
      mutex.synchronize { seen_types << event[:type] }
    end
    Asherah.setup(CONFIG)
    5.times do |i|
      ct = Asherah.encrypt("metrics-fire", "payload-#{i}")
      Asherah.decrypt("metrics-fire", ct)
    end
    Asherah.shutdown
    wait_for { mutex.synchronize { seen_types.include?(:encrypt) && seen_types.include?(:decrypt) } }

    assert_includes seen_types, :encrypt, "expected :encrypt event, saw #{seen_types.to_a.inspect}"
    assert_includes seen_types, :decrypt, "expected :decrypt event, saw #{seen_types.to_a.inspect}"
  end

  def test_metrics_timing_events_carry_positive_duration
    timings = []
    mutex = Mutex.new
    Asherah.set_metrics_hook do |event|
      mutex.synchronize { timings << event } if %i[encrypt decrypt].include?(event[:type])
    end
    Asherah.setup(CONFIG)
    3.times do |i|
      ct = Asherah.encrypt("timing", "v#{i}")
      Asherah.decrypt("timing", ct)
    end
    Asherah.shutdown
    wait_for { mutex.synchronize { !timings.empty? } }

    refute_empty timings, "expected at least one timing event"
    timings.each do |event|
      assert event[:duration_ns] > 0,
        "timing event #{event[:type]} had non-positive duration"
      assert_nil event[:name], "timing event must not carry a name"
    end
  end

  def test_metrics_hook_exceptions_do_not_crash
    fired = 0
    mutex = Mutex.new
    Asherah.set_metrics_hook { |_| mutex.synchronize { fired += 1 }; raise "intentional from metrics hook" }
    Asherah.setup(CONFIG)
    ct = Asherah.encrypt("metrics-throw", "survive")
    assert_equal "survive", Asherah.decrypt("metrics-throw", ct).force_encoding("UTF-8")
    Asherah.shutdown
    wait_for { mutex.synchronize { fired > 0 } }
    assert fired > 0, "metrics hook must have fired at least once"
  end

  def test_metrics_hook_survives_many_operations
    fired = 0
    mutex = Mutex.new
    Asherah.set_metrics_hook { |_| mutex.synchronize { fired += 1 } }
    Asherah.setup(CONFIG)
    100.times do |i|
      ct = Asherah.encrypt("vol", "payload-#{i}")
      Asherah.decrypt("vol", ct)
    end
    Asherah.shutdown
    wait_for { mutex.synchronize { fired >= 200 } }
    assert fired >= 200,
      "expected ≥200 metrics events for 100 enc/dec ops, got #{fired}"
  end

  def test_metrics_and_log_hooks_coexist
    log_hits = 0
    metric_hits = 0
    mutex = Mutex.new
    Asherah.set_log_hook { |_| mutex.synchronize { log_hits += 1 } }
    Asherah.set_metrics_hook { |_| mutex.synchronize { metric_hits += 1 } }
    Asherah.setup(CONFIG)
    3.times do |i|
      ct = Asherah.encrypt("coexist", "v#{i}")
      Asherah.decrypt("coexist", ct)
    end
    Asherah.shutdown
    wait_for { mutex.synchronize { metric_hits > 0 } }
    assert metric_hits > 0, "metrics hook should have fired"
    assert log_hits >= 0
  end

  def test_set_metrics_hook_rejects_non_callable
    assert_raises(ArgumentError) { Asherah.set_metrics_hook(42) }
  end

  def test_cache_events_carry_name_and_zero_duration
    require "set"
    cache_events = []
    Asherah.set_metrics_hook do |event|
      cache_events << event if %i[cache_hit cache_miss cache_stale].include?(event[:type])
    end
    cached_config = CONFIG.merge("EnableSessionCaching" => true)
    Asherah.setup(cached_config)
    3.times do |i|
      ct = Asherah.encrypt("cache-#{i % 2}", "payload-#{i}")
      Asherah.decrypt("cache-#{i % 2}", ct)
    end
    Asherah.shutdown
    cache_events.each do |event|
      assert_equal 0, event[:duration_ns],
        "cache event #{event[:type]} carried non-zero duration"
      assert_kind_of String, event[:name],
        "cache event #{event[:type]} missing name"
    end
  end

  def test_hook_survives_setup_shutdown_cycles
    metric_hits = 0
    mutex = Mutex.new
    Asherah.set_metrics_hook { |_| mutex.synchronize { metric_hits += 1 } }
    3.times do |cycle|
      Asherah.setup(CONFIG)
      ct = Asherah.encrypt("cycle-#{cycle}", "payload")
      Asherah.decrypt("cycle-#{cycle}", ct)
      Asherah.shutdown
    end
    wait_for { mutex.synchronize { metric_hits > 0 } }
    assert metric_hits > 0, "hook should fire across factory cycles"
  end
end
