# frozen_string_literal: true

require_relative "native"

module Asherah
  class Session
    def initialize(pointer)
      raise Asherah::Error::GetSessionFailed, Native.last_error if pointer.null?
      @pointer = pointer
      @close_mu = Mutex.new
      @pending_ops = 0
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

    # True async encrypt — runs on Rust's tokio runtime, does not block the Ruby thread.
    # Returns the result; internally uses a Queue to wait for the tokio callback.
    def encrypt_bytes_async(data)
      raise Asherah::Error::EncryptFailed, "session closed" if @pointer.null?
      @close_mu.synchronize { @pending_ops += 1 }
      queue = Queue.new
      session = self
      callback = FFI::Function.new(:void, [:pointer, :pointer, :size_t, :string]) do |_ud, result_ptr, result_len, error|
        begin
          if error
            queue.push(Asherah::Error::EncryptFailed.new(error))
          else
            queue.push(result_ptr.read_bytes(result_len))
          end
        ensure
          session.send(:decrement_pending_ops)
        end
      end
      status = Native.asherah_encrypt_to_json_async(@pointer, data, data.bytesize, callback, nil)
      unless status.zero?
        @close_mu.synchronize { @pending_ops -= 1 }
        raise Asherah::Error::EncryptFailed, Native.last_error
      end
      result = queue.pop
      raise result if result.is_a?(Exception)
      result
    end

    # True async decrypt — runs on Rust's tokio runtime, does not block the Ruby thread.
    def decrypt_bytes_async(json)
      raise Asherah::Error::DecryptFailed, "session closed" if @pointer.null?
      @close_mu.synchronize { @pending_ops += 1 }
      queue = Queue.new
      session = self
      callback = FFI::Function.new(:void, [:pointer, :pointer, :size_t, :string]) do |_ud, result_ptr, result_len, error|
        begin
          if error
            queue.push(Asherah::Error::DecryptFailed.new(error))
          else
            queue.push(result_ptr.read_bytes(result_len))
          end
        ensure
          session.send(:decrement_pending_ops)
        end
      end
      status = Native.asherah_decrypt_from_json_async(@pointer, json, json.bytesize, callback, nil)
      unless status.zero?
        @close_mu.synchronize { @pending_ops -= 1 }
        raise Asherah::Error::DecryptFailed, Native.last_error
      end
      result = queue.pop
      raise result if result.is_a?(Exception)
      result
    end

    def close
      ptr = @close_mu.synchronize do
        return if @pointer.null?
        # Wait for in-flight async operations before freeing
        sleep 0.001 while @pending_ops > 0
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

    def decrement_pending_ops
      @close_mu.synchronize { @pending_ops -= 1 }
    end

    def thread_local_buffer
      Thread.current[:asherah_buffer] ||= Native::AsherahBuffer.new
    end
  end
end
