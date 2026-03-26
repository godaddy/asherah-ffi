# frozen_string_literal: true

require_relative "native"
require_relative "session"

module Asherah
  class SessionFactory
    def initialize(pointer)
      raise Asherah::Error::BadConfig, Native.last_error if pointer.null?
      @pointer = pointer
      @close_mu = Mutex.new
    end

    def get_session(partition_id)
      raise Asherah::Error::NotInitialized, "factory closed" if @pointer.null?
      id = String(partition_id)
      raise ArgumentError, "partition_id cannot be empty" if id.empty?
      Session.new(Native.asherah_factory_get_session(@pointer, id))
    end

    def close
      ptr = @close_mu.synchronize do
        return if @pointer.null?
        p = @pointer
        @pointer = FFI::Pointer::NULL
        p
      end
      Native.asherah_factory_free(ptr)
    end

    def closed?
      @pointer.null?
    end
  end
end
