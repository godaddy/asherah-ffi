require_relative "native"

module Asherah
  class Session
    def initialize(pointer)
      @pointer = Native.ensure_pointer(pointer)
      @closed = false
      ObjectSpace.define_finalizer(self, self.class.finalizer(@pointer))
    end

    def encrypt_bytes(data)
      ensure_open
      payload = String(data).dup.force_encoding(Encoding::BINARY)
      buffer = Native::AsherahBuffer.malloc
      bytes = Fiddle::Pointer[payload]
      Native.ensure_ok(Native.asherah_encrypt_to_json(@pointer, bytes, payload.bytesize, buffer))
      begin
        Native.read_buffer(buffer).force_encoding(Encoding::UTF_8)
      ensure
        Native.free_buffer(buffer)
      end
    end

    def decrypt_bytes(json)
      ensure_open
      serialized = String(json).dup.force_encoding(Encoding::UTF_8)
      buffer = Native::AsherahBuffer.malloc
      bytes = Fiddle::Pointer[serialized]
      Native.ensure_ok(Native.asherah_decrypt_from_json(@pointer, bytes, serialized.bytesize, buffer))
      begin
        Native.read_buffer(buffer).force_encoding(Encoding::BINARY)
      ensure
        Native.free_buffer(buffer)
      end
    end

    def close
      return if @closed

      ObjectSpace.undefine_finalizer(self)
      begin
        Native.asherah_session_free(@pointer)
      ensure
        @pointer = Native.null_pointer
        @closed = true
      end
    end

    def closed?
      @closed
    end

    protected

    def ensure_open
      raise Asherah::Error, "session closed" if @closed
    end

    def self.finalizer(pointer)
      proc do
        begin
          Native.asherah_session_free(pointer) unless pointer.null?
        rescue StandardError
        end
      end
    end
  end
end
