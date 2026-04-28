# frozen_string_literal: true

require "timeout"
require_relative "native"

module Asherah
  class Session
    # Maximum wall time the async API will wait for the FFI callback to
    # deliver a result before giving up. Without this bound, a hung tokio
    # worker (or any callback-delivery race) would block the calling Ruby
    # thread until the process exits — observed as 6-hour CI hangs on the
    # round-trip tests. Override via ASHERAH_RUBY_ASYNC_TIMEOUT (seconds).
    DEFAULT_ASYNC_TIMEOUT_SECONDS = 30

    # Maximum time {#close} will wait for in-flight async operations to
    # drain before forcibly freeing the session. Independent of the
    # per-call async timeout above.
    DEFAULT_CLOSE_DRAIN_SECONDS = 5

    def self.async_timeout_seconds
      val = ENV["ASHERAH_RUBY_ASYNC_TIMEOUT"]
      return DEFAULT_ASYNC_TIMEOUT_SECONDS if val.nil? || val.empty?
      Float(val)
    rescue ArgumentError, TypeError
      DEFAULT_ASYNC_TIMEOUT_SECONDS
    end

    def initialize(pointer)
      raise Asherah::Error::GetSessionFailed, Native.last_error if pointer.null?
      @pointer = pointer
      @close_mu = Mutex.new
      @pending_ops = 0
    end

    def encrypt_bytes(data)
      raise ArgumentError, "data cannot be nil" if data.nil?
      raise Asherah::Error::EncryptFailed, "session closed" if @pointer.null?
      buf = thread_local_buffer
      status = Native.asherah_encrypt_to_json(@pointer, data, data.bytesize, buf.pointer)
      raise Asherah::Error::EncryptFailed, Native.last_error unless status.zero?
      result = buf[:data].read_bytes(buf[:len])
      Native.asherah_buffer_free(buf.pointer)
      result
    end

    def decrypt_bytes(json)
      raise ArgumentError, "json cannot be nil" if json.nil?
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
      raise ArgumentError, "data cannot be nil" if data.nil?
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
      # Bound the wait so a wedged callback can't block the calling
      # thread forever. We use Timeout.timeout (not Queue#pop(timeout:),
      # which only landed in Ruby 3.2) so the lib remains usable on the
      # 3.0/3.1 Ruby builds still in some CI/test images.
      result = await_async_result(queue, "encrypt_bytes_async")
      raise result if result.is_a?(Exception)
      result
    end

    # True async decrypt — runs on Rust's tokio runtime, does not block the Ruby thread.
    def decrypt_bytes_async(json)
      raise ArgumentError, "json cannot be nil" if json.nil?
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
      result = await_async_result(queue, "decrypt_bytes_async")
      raise result if result.is_a?(Exception)
      result
    end

    def close
      ptr = @close_mu.synchronize do
        return if @pointer.null?
        # Wait for in-flight async operations before freeing, but bound
        # the wait — a wedged callback used to make this spin forever
        # (and silently wedge any process trying to shut down cleanly).
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + DEFAULT_CLOSE_DRAIN_SECONDS
        while @pending_ops > 0 && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
          sleep 0.001
        end
        if @pending_ops > 0
          warn "asherah: closing session with #{@pending_ops} async operation(s) " \
               "still in flight after #{DEFAULT_CLOSE_DRAIN_SECONDS}s drain"
        end
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

    # Wait up to {Session.async_timeout_seconds} for the FFI callback
    # to push a result onto +queue+. On expiry, raise
    # {Asherah::Error::Timeout}; the late callback (if it eventually
    # fires) still decrements the pending-op counter via its `ensure`
    # block, so close() can drain cleanly.
    def await_async_result(queue, label)
      ::Timeout.timeout(Session.async_timeout_seconds) { queue.pop }
    rescue ::Timeout::Error
      raise Asherah::Error::Timeout,
            "#{label} timed out after #{Session.async_timeout_seconds}s"
    end

    def decrement_pending_ops
      @close_mu.synchronize { @pending_ops -= 1 }
    end

    def thread_local_buffer
      Thread.current[:asherah_buffer] ||= Native::AsherahBuffer.new
    end
  end
end
