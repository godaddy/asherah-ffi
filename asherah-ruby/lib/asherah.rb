# frozen_string_literal: true

require "json"

require_relative "asherah/error"
require_relative "asherah/config"
require_relative "asherah/native"
require_relative "asherah/session_factory"
require_relative "asherah/session"

module Asherah
  @mutex = Mutex.new
  @factory = nil
  @sessions = {}
  @initialized = false
  @session_cache_enabled = true
  @log_hook = nil
  @verbose = false
  @max_stack_alloc_item_size = nil
  @safety_padding_overhead = nil

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
      end
      config = Config.new
      yield config
      setup(config.to_h)
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
        rescue StandardError
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

    def setenv(env)
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
      session = resolve_session(partition_id)
      session.encrypt_bytes(payload)
    end

    def encrypt_string(partition_id, text)
      encrypt(partition_id, text.to_s)
    end

    def decrypt(partition_id, data_row_record)
      session = resolve_session(partition_id)
      session.decrypt_bytes(data_row_record).force_encoding(Encoding::UTF_8)
    end

    def decrypt_string(partition_id, data_row_record)
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

    def set_max_stack_alloc_item_size(bytes)
      @mutex.synchronize do
        @max_stack_alloc_item_size = Integer(bytes)
      end
      nil
    end

    def set_safety_padding_overhead(bytes)
      @mutex.synchronize do
        @safety_padding_overhead = Integer(bytes)
      end
      nil
    rescue ArgumentError, TypeError
      @safety_padding_overhead = nil
      nil
    end

    def set_log_hook(&block)
      raise ArgumentError, "log hook block required" unless block

      @mutex.synchronize do
        @log_hook = block
      end
      nil
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
