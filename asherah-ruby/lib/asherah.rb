# frozen_string_literal: true

require "json"

require_relative "asherah/version"
require_relative "asherah/error"
require_relative "asherah/config"
require_relative "asherah/native"
require_relative "asherah/session_factory"
require_relative "asherah/session"
require_relative "asherah/hooks"

module Asherah
  @mutex = Mutex.new
  @factory = nil
  @sessions = {}
  @initialized = false
  @session_cache_enabled = true
  @verbose = false

  class << self
    # Configure Asherah using a block with snake_case accessors.
    # Compatible with the canonical godaddy/asherah-ruby gem API.
    #
    #   Asherah.configure do |config|
    #     config.service_name = "MyService"
    #     config.product_id = "MyProduct"
    #     config.kms = "static"
    #     config.metastore = "memory"
    #   end
    def configure
      @mutex.synchronize do
        raise Error::AlreadyInitialized if @initialized

        config = Config.new
        yield config
        config.validate!

        json = config.to_json
        pointer = Native.asherah_factory_new_with_config(json)
        @factory = SessionFactory.new(pointer)
        @sessions = {}
        @initialized = true
        @session_cache_enabled = config.enable_session_caching != false
        @verbose = config.verbose == true
      end
    end

    # Initialize Asherah with a PascalCase config hash.
    # Also accepts snake_case string/symbol keys (auto-normalized).
    def setup(config)
      normalized = normalize_config(config)
      json = JSON.generate(normalized)

      pointer = Native.asherah_factory_new_with_config(json)
      factory = SessionFactory.new(pointer)

      @mutex.synchronize do
        raise Error::AlreadyInitialized if @initialized

        @factory = factory
        @sessions = {}
        @initialized = true
        @session_cache_enabled = truthy(normalized["EnableSessionCaching"], default: true)
        @verbose = truthy(normalized["Verbose"], default: false)
      end

      nil
    rescue StandardError
      factory&.close if defined?(factory) && factory
      raise
    end

    def setup_async(config, &block)
      Thread.new do
        result = setup(config)
        block&.call(result)
        result
      end
    end

    def shutdown
      factory = nil
      sessions = nil
      @mutex.synchronize do
        raise Error::NotInitialized unless @initialized

        factory = @factory
        sessions = @sessions.values
        @factory = nil
        @sessions = {}
        @initialized = false
      end

      Array(sessions).each do |session|
        begin
          session.close unless session.closed?
        rescue StandardError => e
          warn "asherah: error closing session during shutdown: #{e.message}"
        end
      end
      factory&.close unless factory&.closed?
      nil
    end

    def shutdown_async(&block)
      Thread.new do
        result = shutdown
        block&.call(result)
        result
      end
    end

    def get_setup_status
      @mutex.synchronize { @initialized }
    end

    def setenv(env = {})
      data = case env
             when String
               JSON.parse(env)
             else
               env
             end
      unless data.respond_to?(:each_pair)
        raise ArgumentError, "environment payload must be a Hash or JSON object"
      end
      data.each_pair do |k, v|
        if v.nil?
          ENV.delete(String(k))
        else
          ENV[String(k)] = v.to_s
        end
      end
      nil
    end
    alias_method :set_env, :setenv

    def encrypt(partition_id, payload)
      raise ArgumentError, "payload cannot be nil" if payload.nil?
      session = resolve_session(partition_id)
      session.encrypt_bytes(payload)
    end

    def encrypt_string(partition_id, text)
      raise ArgumentError, "text cannot be nil" if text.nil?
      encrypt(partition_id, text)
    end

    def decrypt(partition_id, data_row_record)
      raise ArgumentError, "data_row_record cannot be nil" if data_row_record.nil?
      session = resolve_session(partition_id)
      session.decrypt_bytes(data_row_record).force_encoding(Encoding::UTF_8)
    end

    def decrypt_string(partition_id, data_row_record)
      raise ArgumentError, "data_row_record cannot be nil" if data_row_record.nil?
      decrypt(partition_id, data_row_record).force_encoding(Encoding::UTF_8)
    end

    def encrypt_async(partition_id, payload, &block)
      Thread.new do
        result = encrypt(partition_id, payload)
        block&.call(result)
        result
      end
    end

    def decrypt_async(partition_id, data_row_record, &block)
      Thread.new do
        result = decrypt(partition_id, data_row_record)
        block&.call(result)
        result
      end
    end

    # Install a log hook. Yields a +Hash+ +{level:, target:, message:}+ for
    # every log record emitted by the underlying Rust crates. The block may
    # fire from any thread; implementations must be thread-safe and
    # non-blocking. Pass +nil+ to clear (equivalent to {clear_log_hook}).
    #
    # Replaces any previously installed log hook. Exceptions raised from the
    # callback are caught and silently swallowed.
    def set_log_hook(callback = nil, &block)
      Hooks.set_log_hook(callback, &block)
    end

    # Remove the active log hook, if any. Idempotent.
    def clear_log_hook
      Hooks.clear_log_hook
    end

    # Install a metrics hook. Yields a +Hash+ +{type:, duration_ns:, name:}+
    # for every metrics event. Timing events ({:encrypt, :decrypt, :store,
    # :load}) carry a positive +duration_ns+ and a +nil+ +name+; cache events
    # ({:cache_hit, :cache_miss, :cache_stale}) carry +duration_ns+ == 0 and
    # the cache identifier in +name+.
    #
    # Installing a hook implicitly enables the global metrics gate; clearing
    # it disables the gate. Replaces any previously installed metrics hook.
    # Pass +nil+ to clear (equivalent to {clear_metrics_hook}).
    def set_metrics_hook(callback = nil, &block)
      Hooks.set_metrics_hook(callback, &block)
    end

    # Remove the active metrics hook and disable metrics. Idempotent.
    def clear_metrics_hook
      Hooks.clear_metrics_hook
    end

    private

    REQUIRED_KEYS = %w[ServiceName ProductID Metastore].freeze

    def normalize_config(config)
      unless config.respond_to?(:each_pair)
        raise ArgumentError, "config must be a Hash-like object"
      end
      normalized = {}
      config.each_pair do |key, value|
        normalized[String(key)] = value
      end
      REQUIRED_KEYS.each do |key|
        raise ArgumentError, "#{key} is required" if normalized[key].nil? || normalized[key].to_s.strip.empty?
      end
      normalized
    end

    def truthy(value, default: false)
      return default if value.nil?

      case value
      when true, "1", "true", "TRUE", "yes", "on" then true
      when false, "0", "false", "FALSE", "no", "off" then false
      else
        default
      end
    end

    def resolve_session(partition_id)
      raise ArgumentError, "partition_id cannot be empty" if String(partition_id).empty?

      # Brief mutex hold for hash lookup only — FFI call happens outside
      @mutex.synchronize do
        raise Error::NotInitialized unless @initialized
        if @session_cache_enabled
          @sessions[partition_id] ||= @factory.get_session(partition_id)
        else
          @factory.get_session(partition_id)
        end
      end
    end
  end
end
