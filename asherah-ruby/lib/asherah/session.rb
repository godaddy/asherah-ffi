# frozen_string_literal: true

require_relative "native"

module Asherah
  class Session
    def initialize(pointer)
      raise Asherah::Error::GetSessionFailed, Native.last_error if pointer.null?
      @pointer = pointer
      @close_mu = Mutex.new
    end

    def encrypt_bytes(data)
      raise Asherah::Error::EncryptFailed, "session closed" if @pointer.null?
      buf = thread_local_buffer
      status = Native.asherah_encrypt_to_json(@pointer, data, data.bytesize, buf.pointer)
      raise Asherah::Error::EncryptFailed, Native.last_error unless status.zero?
      result = buf[:data].read_bytes(buf[:len])
      Native.asherah_buffer_free(buf.pointer)
      result
    end

    def decrypt_bytes(json)
      raise Asherah::Error::DecryptFailed, "session closed" if @pointer.null?
      buf = thread_local_buffer
      status = Native.asherah_decrypt_from_json(@pointer, json, json.bytesize, buf.pointer)
      raise Asherah::Error::DecryptFailed, Native.last_error unless status.zero?
      result = buf[:data].read_bytes(buf[:len])
      Native.asherah_buffer_free(buf.pointer)
      result
    end

    def close
      ptr = @close_mu.synchronize do
        return if @pointer.null?
        p = @pointer
        @pointer = FFI::Pointer::NULL
        p
      end
      Native.asherah_session_free(ptr)
    end

    def closed?
      @pointer.null?
    end

    private

    def thread_local_buffer
      Thread.current[:asherah_buffer] ||= Native::AsherahBuffer.new
    end
  end
end
