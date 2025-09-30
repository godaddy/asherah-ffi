require "fiddle"
require "fiddle/import"
require "rbconfig"

require_relative "error"

module Asherah
  module Native
    extend Fiddle::Importer

    def self.library_basenames
      host = RbConfig::CONFIG["host_os"]
      if host =~ /mswin|mingw|cygwin/
        ["asherah_ffi.dll"]
      elsif host =~ /darwin/
        ["libasherah_ffi.dylib"]
      else
        ["libasherah_ffi.so"]
      end
    end

    def self.candidate_paths
      names = library_basenames
      env = ENV.fetch("ASHERAH_RUBY_NATIVE", "").strip
      paths = []
      unless env.empty?
        if File.directory?(env)
          names.each { |name| paths << File.join(env, name) }
        else
          paths << env
        end
      end
      cargo_target = ENV.fetch("CARGO_TARGET_DIR", "").strip
      unless cargo_target.empty?
        %w[debug release].each do |profile|
          names.each do |name|
            paths << File.join(cargo_target, profile, name)
          end
        end
      end

      root = File.expand_path("../../..", __dir__)
      %w[target/debug target/release].each do |sub|
        names.each do |name|
          paths << File.join(root, sub, name)
        end
      end
      names.each { |name| paths << name }
      paths.uniq
    end

    def self.resolve_library
      candidate_paths.find { |path| File.exist?(path) } || candidate_paths.first
    end

    LIBRARY_PATH = resolve_library

    dlload LIBRARY_PATH

    AsherahBuffer = struct(
      [
        "void* data",
        "size_t len",
      ],
    )

    extern "const char* asherah_last_error_message()"
    extern "void* asherah_factory_new_from_env()"
    extern "int asherah_apply_config_json(const char*)"
    extern "void* asherah_factory_new_with_config(const char*)"
    extern "void asherah_factory_free(void*)"
    extern "void* asherah_factory_get_session(void*, const char*)"
    extern "void asherah_session_free(void*)"
    extern "int asherah_encrypt_to_json(void*, const unsigned char*, size_t, struct AsherahBuffer*)"
    extern "int asherah_decrypt_from_json(void*, const unsigned char*, size_t, struct AsherahBuffer*)"
    extern "void asherah_buffer_free(struct AsherahBuffer*)"

    def self.null_pointer
      @null_pointer ||= Fiddle::Pointer.new(0)
    end

    def self.ensure_pointer(ptr)
      if ptr.null?
        raise Asherah::Error, last_error
      end
      ptr
    end

    def self.ensure_ok(status)
      return if status.zero?

      raise Asherah::Error, last_error
    end

    def self.apply_config(json)
      ensure_ok(asherah_apply_config_json(json))
    end

    def self.factory_from_config(json)
      ensure_pointer(asherah_factory_new_with_config(json))
    end

    def self.last_error
      ptr = asherah_last_error_message
      return "unknown error" if ptr.null?

      ptr.to_s
    end

    def self.read_buffer(buffer)
      pointer = buffer.data
      length = buffer.len
      return "" if length.zero?

      if pointer.respond_to?(:null?) && pointer.null?
        ""
      else
        raw = pointer.respond_to?(:to_ptr) ? pointer.to_ptr : Fiddle::Pointer.new(pointer)
        raw[0, length]
      end
    end

    def self.free_buffer(buffer)
      asherah_buffer_free(buffer) unless buffer.nil?
    end

    private_class_method :library_basenames, :candidate_paths, :resolve_library
  end
end
