# frozen_string_literal: true

require "ffi"
require "rbconfig"
require_relative "error"

module Asherah
  module Native
    extend FFI::Library

    class AsherahBuffer < FFI::Struct
      layout :data, :pointer, :len, :size_t, :capacity, :size_t
    end

    class << self
      def library_basenames
        host = RbConfig::CONFIG["host_os"]
        if host =~ /mswin|mingw|cygwin/
          ["asherah_ffi.dll"]
        elsif host =~ /darwin/
          ["libasherah_ffi.dylib"]
        else
          ["libasherah_ffi.so"]
        end
      end

      def candidate_paths
        names = library_basenames
        paths = []

        # 1. Explicit override via environment variable
        env = ENV.fetch("ASHERAH_RUBY_NATIVE", "").strip
        unless env.empty?
          if File.directory?(env)
            names.each { |name| paths << File.join(env, name) }
          else
            paths << env
          end
        end

        # 2. Bundled in gem (platform-specific gem ships it here)
        native_dir = File.expand_path("native", __dir__)
        names.each { |name| paths << File.join(native_dir, name) }

        # 3. CARGO_TARGET_DIR (development)
        cargo_target = ENV.fetch("CARGO_TARGET_DIR", "").strip
        unless cargo_target.empty?
          %w[debug release].each do |profile|
            names.each { |name| paths << File.join(cargo_target, profile, name) }
          end
        end

        # 4. Workspace target directory (development)
        root = File.expand_path("../../..", __dir__)
        %w[target/release target/debug].each do |sub|
          names.each { |name| paths << File.join(root, sub, name) }
        end

        # 5. System library path fallback
        names.each { |name| paths << name }
        paths.uniq
      end

      def resolve_library
        candidate_paths.find { |path| File.exist?(path) } || candidate_paths.first
      end
    end

    LIBRARY_PATH = resolve_library
    ffi_lib LIBRARY_PATH

    attach_function :asherah_last_error_message, [], :pointer
    attach_function :asherah_factory_new_from_env, [], :pointer
    attach_function :asherah_factory_new_with_config, [:string], :pointer
    attach_function :asherah_apply_config_json, [:string], :int
    attach_function :asherah_factory_free, [:pointer], :void
    attach_function :asherah_factory_get_session, [:pointer, :string], :pointer
    attach_function :asherah_session_free, [:pointer], :void
    attach_function :asherah_encrypt_to_json, [:pointer, :buffer_in, :size_t, :pointer], :int
    attach_function :asherah_decrypt_from_json, [:pointer, :buffer_in, :size_t, :pointer], :int
    attach_function :asherah_buffer_free, [:pointer], :void

    # Async callback type: void(user_data, result_data, result_len, error_message)
    callback :asherah_completion_fn, [:pointer, :pointer, :size_t, :string], :void
    attach_function :asherah_encrypt_to_json_async,
                    [:pointer, :buffer_in, :size_t, :asherah_completion_fn, :pointer], :int
    attach_function :asherah_decrypt_from_json_async,
                    [:pointer, :buffer_in, :size_t, :asherah_completion_fn, :pointer], :int

    # Log + metrics hooks. The C ABI does not own the callback closure — Ruby
    # must keep a reference to the FFI::Function it passes here for as long as
    # the hook is registered, otherwise the GC will collect it and the next
    # invocation segfaults. The Asherah module pins the active hooks in module
    # state.
    callback :asherah_log_callback, [:pointer, :int, :string, :string], :void
    callback :asherah_metrics_callback, [:pointer, :int, :uint64, :string], :void

    attach_function :asherah_set_log_hook, [:asherah_log_callback, :pointer], :int
    attach_function :asherah_clear_log_hook, [], :int
    attach_function :asherah_set_metrics_hook, [:asherah_metrics_callback, :pointer], :int
    attach_function :asherah_clear_metrics_hook, [], :int

    # Log severity constants (mirrors hooks.rs).
    LOG_TRACE = 0
    LOG_DEBUG = 1
    LOG_INFO  = 2
    LOG_WARN  = 3
    LOG_ERROR = 4

    # Metrics event type constants (mirrors hooks.rs).
    METRIC_ENCRYPT     = 0
    METRIC_DECRYPT     = 1
    METRIC_STORE       = 2
    METRIC_LOAD        = 3
    METRIC_CACHE_HIT   = 4
    METRIC_CACHE_MISS  = 5
    METRIC_CACHE_STALE = 6

    def self.last_error
      ptr = asherah_last_error_message
      ptr.null? ? "unknown error" : ptr.read_string
    end

    private_class_method :library_basenames, :candidate_paths, :resolve_library
  end
end
