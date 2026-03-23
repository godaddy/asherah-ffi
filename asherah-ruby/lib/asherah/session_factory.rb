# frozen_string_literal: true

require_relative "native"
require_relative "session"

module Asherah
  class SessionFactory
    def initialize(pointer = nil)
      ptr = pointer || Native.asherah_factory_new_from_env
      raise Asherah::Error::BadConfig, Native.last_error if ptr.null?
      @pointer = ptr
      @closed = false
      ObjectSpace.define_finalizer(self, self.class.make_finalizer(ptr))
    end

    def get_session(partition_id)
      raise Asherah::Error::NotInitialized, "factory closed" if @closed
      id = String(partition_id)
      raise ArgumentError, "partition_id cannot be empty" if id.empty?
      Session.new(Native.asherah_factory_get_session(@pointer, id))
    end

    def close
      return if @closed
      ObjectSpace.undefine_finalizer(self)
      begin
        Native.asherah_factory_free(@pointer)
      ensure
        @pointer = FFI::Pointer::NULL
        @closed = true
      end
    end

    def closed?
      @closed
    end

    def self.make_finalizer(pointer)
      proc do
        begin
          Native.asherah_factory_free(pointer) unless pointer.null?
        rescue StandardError
        end
      end
    end
  end
end
