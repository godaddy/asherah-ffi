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

    def self.last_error
      ptr = asherah_last_error_message
      ptr.null? ? "unknown error" : ptr.read_string
    end

    private_class_method :library_basenames, :candidate_paths, :resolve_library
  end
end
