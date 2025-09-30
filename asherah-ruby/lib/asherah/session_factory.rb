require_relative "native"
require_relative "session"

module Asherah
  class SessionFactory
    def initialize(pointer = nil)
      allocated = pointer || Native.asherah_factory_new_from_env
      @pointer = Native.ensure_pointer(allocated)
      @closed = false
      ObjectSpace.define_finalizer(self, self.class.finalizer(@pointer))
    end

    def get_session(partition_id)
      ensure_open
      id = String(partition_id)
      raise ArgumentError, "partition_id cannot be empty" if id.empty?

      Session.new(Native.ensure_pointer(Native.asherah_factory_get_session(@pointer, id)))
    end

    def close
      return if @closed

      ObjectSpace.undefine_finalizer(self)
      begin
        Native.asherah_factory_free(@pointer)
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
      raise Asherah::Error, "factory closed" if @closed
    end

    def self.finalizer(pointer)
      proc do
        begin
          Native.asherah_factory_free(pointer) unless pointer.null?
        rescue StandardError
        end
      end
    end
  end
end
