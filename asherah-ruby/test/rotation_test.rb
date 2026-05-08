# Rotation, revocation, and sync↔async interop tests for the
# asherah-ruby binding.
#
# The Rust core has comprehensive rotation/revocation coverage in
# asherah/tests/. The Ruby binding had zero rotation tests prior to
# this file. Mirrors the asherah-node, asherah-py, asherah-java,
# asherah-dotnet, and asherah-go rotation suites.
#
# Hermetic: Metastore: 'memory' + KMS: 'test-debug-static' produces a
# hermetic factory with no Docker or network dependency.

require "json"
require_relative "test_helper"

class RotationTest < Minitest::Test
  def short_expiry_config(suffix)
    {
      "ServiceName" => "rot-#{suffix}-svc",
      "ProductID" => "rot-#{suffix}-prod",
      "Metastore" => "memory",
      "KMS" => "test-debug-static",
      "ExpireAfter" => 1,
      "CheckInterval" => 1,
      "EnableSessionCaching" => false,
    }
  end

  def setup
    ENV["SERVICE_NAME"] = "svc"
    ENV["PRODUCT_ID"] = "prod"
    ENV["KMS"] = "test-debug-static"
    ENV["STATIC_MASTER_KEY_HEX"] = "22" * 32
  end

  def teardown
    Asherah.shutdown if Asherah.get_setup_status
  rescue Asherah::Error::NotInitialized
    # already shut down
  end

  # Pull Key.ParentKeyMeta.Created out of a DRR JSON string. The Rust
  # core uses Pascal-cased fields for cross-language compatibility.
  def ik_created(drr_json)
    parsed = JSON.parse(drr_json)
    refute_nil parsed["Key"], "DRR missing Key: #{drr_json}"
    refute_nil parsed["Key"]["ParentKeyMeta"], "DRR missing ParentKeyMeta: #{drr_json}"
    parsed["Key"]["ParentKeyMeta"]["Created"]
  end

  # ──────────── Sync rotation ────────────

  def test_sync_rotation_across_expiry
    Asherah.setup(short_expiry_config("sync"))

    drr1 = Asherah.encrypt("p1", "before")
    ik1 = ik_created(drr1)

    sleep 3

    drr2 = Asherah.encrypt("p1", "after")
    ik2 = ik_created(drr2)

    assert_operator ik2, :>, ik1,
      "expected IK rotation across expiry: ik2=#{ik2} should be > ik1=#{ik1}"
    assert_equal "before", Asherah.decrypt("p1", drr1).force_encoding("UTF-8")
    assert_equal "after", Asherah.decrypt("p1", drr2).force_encoding("UTF-8")
  end

  # ──────────── Async rotation ────────────

  def test_async_rotation_across_expiry
    Asherah.setup(short_expiry_config("async"))

    t1 = Asherah.encrypt_async("p1", "before-async")
    drr1 = t1.value
    ik1 = ik_created(drr1)

    sleep 3

    t2 = Asherah.encrypt_async("p1", "after-async")
    drr2 = t2.value
    ik2 = ik_created(drr2)

    assert_operator ik2, :>, ik1,
      "async path must rotate IK across expiry: ik2=#{ik2} should be > ik1=#{ik1}"

    assert_equal "before-async",
      Asherah.decrypt_async("p1", drr1).value.force_encoding("UTF-8")
    assert_equal "after-async",
      Asherah.decrypt_async("p1", drr2).value.force_encoding("UTF-8")
  end

  # ──────────── Sync↔async interop after rotation ────────────

  def test_sync_async_interop_after_rotation
    Asherah.setup(short_expiry_config("interop"))

    drr_sync_pre = Asherah.encrypt("p1", "sync-pre")
    drr_async_pre = Asherah.encrypt_async("p1", "async-pre").value

    sleep 3

    drr_sync_post = Asherah.encrypt("p1", "sync-post")
    drr_async_post = Asherah.encrypt_async("p1", "async-post").value

    pre_max = [ik_created(drr_sync_pre), ik_created(drr_async_pre)].max
    post_min = [ik_created(drr_sync_post), ik_created(drr_async_post)].min
    assert_operator post_min, :>, pre_max,
      "interop path must rotate: postMin=#{post_min} should be > preMax=#{pre_max}"

    # 8 round-trips: every encrypt × every decrypt path.
    [
      [drr_sync_pre, "sync-pre"],
      [drr_async_pre, "async-pre"],
      [drr_sync_post, "sync-post"],
      [drr_async_post, "async-post"],
    ].each do |drr, expected|
      assert_equal expected,
        Asherah.decrypt("p1", drr).force_encoding("UTF-8"),
        "sync decrypt of #{expected.inspect}"
      assert_equal expected,
        Asherah.decrypt_async("p1", drr).value.force_encoding("UTF-8"),
        "async decrypt of #{expected.inspect}"
    end
  end

  # ──────────── Multiple rotation cycles ────────────

  def test_multiple_rotation_cycles
    Asherah.setup(short_expiry_config("multi"))

    history = []
    3.times do |i|
      payload = "cycle-#{i}"
      drr = Asherah.encrypt_async("p1", payload).value
      history << { drr: drr, payload: payload, ik: ik_created(drr) }
      sleep 3
    end

    # Each cycle's IK must be strictly newer than the previous.
    history.each_cons(2) do |prev, curr|
      assert_operator curr[:ik], :>, prev[:ik],
        "cycle: ik=#{curr[:ik]} should be > prev ik=#{prev[:ik]}"
    end

    # Every historical DRR still decrypts.
    history.each do |entry|
      recovered = Asherah.decrypt_async("p1", entry[:drr]).value.force_encoding("UTF-8")
      assert_equal entry[:payload], recovered
    end
  end
end
