# frozen_string_literal: true

require "logger"

require_relative "native"

module Asherah
  # Log + metrics observability hooks.
  #
  # The C ABI accepts a single function pointer per hook. We marshal each
  # invocation into a Ruby Hash with symbol keys and yield it to the
  # user-provided +Proc+. Exceptions raised by the user's callback are caught
  # and silently swallowed — propagating an exception across the FFI boundary
  # would be undefined behavior (and since Rust 1.81 aborts the process).
  #
  # The user's callback may fire from any thread (Rust tokio worker threads,
  # database driver threads). Implementations must be thread-safe and should
  # not block; expensive forwarding (e.g. to a logging framework) should be
  # done by enqueueing work onto a background thread you own.
  module Hooks
    # Map C ABI integer log level → +Logger::Severity+ constant. The Rust
    # +log+ crate has a TRACE level that stdlib +Logger+ does not; it is
    # surfaced as +Logger::DEBUG+ so the value is still meaningful when the
    # caller dispatches via +Logger#add+.
    LOG_LEVEL_TO_SEVERITY = {
      Native::LOG_TRACE => Logger::DEBUG,
      Native::LOG_DEBUG => Logger::DEBUG,
      Native::LOG_INFO  => Logger::INFO,
      Native::LOG_WARN  => Logger::WARN,
      Native::LOG_ERROR => Logger::ERROR
    }.freeze
    private_constant :LOG_LEVEL_TO_SEVERITY

    # Map +Logger::Severity+ → lowercase symbol for ergonomic dispatch on
    # the raw block API.
    SEVERITY_TO_SYMBOL = {
      Logger::DEBUG => :debug,
      Logger::INFO  => :info,
      Logger::WARN  => :warn,
      Logger::ERROR => :error,
      Logger::FATAL => :fatal,
      Logger::UNKNOWN => :unknown
    }.freeze
    private_constant :SEVERITY_TO_SYMBOL

    METRIC_TYPE_NAMES = {
      Native::METRIC_ENCRYPT     => :encrypt,
      Native::METRIC_DECRYPT     => :decrypt,
      Native::METRIC_STORE       => :store,
      Native::METRIC_LOAD        => :load,
      Native::METRIC_CACHE_HIT   => :cache_hit,
      Native::METRIC_CACHE_MISS  => :cache_miss,
      Native::METRIC_CACHE_STALE => :cache_stale
    }.freeze
    private_constant :METRIC_TYPE_NAMES

    # Module state: pinning the active FFI::Function trampolines is required
    # so the GC does not free them while the C ABI still holds the pointer.
    @mutex = Mutex.new
    @log_trampoline  = nil
    @metrics_trampoline = nil
    @log_callback    = nil
    @metrics_callback = nil
    # Re-entrancy guard. The +ffi+ gem itself can log via its own internal
    # paths during marshalling, and the Rust crates we bridge to log freely.
    # Without this guard a user callback that itself produces log output
    # would re-enter the trampoline and recurse.
    @log_in_callback = {}
    @metrics_in_callback = {}

    class << self
      # Install a log hook. Three forms are supported:
      #
      # 1. A stdlib +Logger+ instance (or any Logger-compatible object that
      #    responds to +#add+, +#debug+, +#info+, +#warn+, +#error+):
      #
      #      Asherah.set_log_hook(Logger.new($stdout))
      #
      #    Each Asherah record is forwarded via
      #    +Logger#add(severity, message, target)+ so the logger's own filter
      #    rules and formatters apply. The +target+ argument is passed as
      #    +progname+ for routing.
      #
      # 2. A +Proc+ or block, yielded a Hash:
      #
      #      Asherah.set_log_hook do |event|
      #        # event[:level]    => :debug | :info | :warn | :error  (symbol)
      #        # event[:severity] => Logger::DEBUG ...  (Logger::Severity int)
      #        # event[:target]   => "asherah::session"
      #        # event[:message]  => "..."
      #      end
      #
      # 3. +nil+ to clear (equivalent to {clear_log_hook}).
      #
      # Replaces any previously installed log hook. Exceptions raised from
      # the callback are caught and silently swallowed.
      def set_log_hook(callback = nil, &block)
        callback ||= block
        if callback.nil?
          clear_log_hook
          return
        end
        callback = logger_to_callback(callback) if logger_like?(callback)
        unless callback.respond_to?(:call)
          raise ArgumentError, "log hook must be a Logger, Proc, or block"
        end

        @mutex.synchronize do
          @log_callback = callback
          # Allocate the trampoline OUTSIDE the user block so a slow user
          # callback can't hold the mutex.
          @log_trampoline = FFI::Function.new(
            :void,
            [:pointer, :int, :string, :string]
          ) do |_user_data, level, target, message|
            dispatch_log(level, target, message)
          end
          rc = Native.asherah_set_log_hook(@log_trampoline, FFI::Pointer::NULL)
          raise Error, "asherah_set_log_hook failed: rc=#{rc}" if rc != 0
        end
        nil
      end

      # Remove the active log hook. Idempotent.
      def clear_log_hook
        @mutex.synchronize do
          Native.asherah_clear_log_hook
          @log_callback = nil
          @log_trampoline = nil
        end
        nil
      end

      # Install a metrics hook. +block+ receives a Hash:
      #
      #   # Timing event:
      #   { type: :encrypt|:decrypt|:store|:load, duration_ns: Integer, name: nil }
      #   # Cache event:
      #   { type: :cache_hit|:cache_miss|:cache_stale, duration_ns: 0, name: String }
      #
      # Installing a hook implicitly enables the global metrics gate; clearing
      # it disables the gate. Replaces any previously installed metrics hook.
      # Pass +nil+ to clear.
      def set_metrics_hook(callback = nil, &block)
        callback ||= block
        if callback.nil?
          clear_metrics_hook
          return
        end
        unless callback.respond_to?(:call)
          raise ArgumentError, "metrics hook must be callable (Proc or block)"
        end

        @mutex.synchronize do
          @metrics_callback = callback
          @metrics_trampoline = FFI::Function.new(
            :void,
            [:pointer, :int, :uint64, :string]
          ) do |_user_data, type, duration_ns, name|
            dispatch_metric(type, duration_ns, name)
          end
          rc = Native.asherah_set_metrics_hook(@metrics_trampoline, FFI::Pointer::NULL)
          raise Error, "asherah_set_metrics_hook failed: rc=#{rc}" if rc != 0
        end
        nil
      end

      # Remove the active metrics hook and disable the metrics gate. Idempotent.
      def clear_metrics_hook
        @mutex.synchronize do
          Native.asherah_clear_metrics_hook
          @metrics_callback = nil
          @metrics_trampoline = nil
        end
        nil
      end

      private

      # Duck-typed Logger detection: anything that is NOT a +Proc+/+Method+
      # and responds to the core stdlib +Logger+ API is treated as a Logger
      # instance. This catches stdlib +Logger+, +ActiveSupport::Logger+,
      # +SemanticLogger+, +Ougai+, etc.
      def logger_like?(obj)
        return false if obj.is_a?(Proc) || obj.is_a?(Method)
        %i[debug info warn error add].all? { |m| obj.respond_to?(m) }
      end

      def logger_to_callback(logger)
        lambda do |event|
          severity = event[:severity] || Logger::ERROR
          # Logger#add(severity, msg, progname) — progname carries target so
          # custom formatters can route on it.
          logger.add(severity, event[:message], event[:target])
        end
      end

      def dispatch_log(level, target, message)
        tid = Thread.current.object_id
        return if @log_in_callback[tid]
        @log_in_callback[tid] = true
        cb = @log_callback
        return if cb.nil?
        begin
          severity = LOG_LEVEL_TO_SEVERITY[level] || Logger::ERROR
          cb.call(
            level: SEVERITY_TO_SYMBOL[severity] || :error,
            severity: severity,
            target: target.to_s,
            message: message.to_s
          )
        rescue StandardError, ScriptError
          # swallow — exceptions across FFI are undefined behavior
        ensure
          @log_in_callback.delete(tid)
        end
      end

      def dispatch_metric(type, duration_ns, name)
        tid = Thread.current.object_id
        return if @metrics_in_callback[tid]
        @metrics_in_callback[tid] = true
        cb = @metrics_callback
        return if cb.nil?
        begin
          cb.call(
            type: METRIC_TYPE_NAMES[type] || :encrypt,
            duration_ns: duration_ns,
            name: name
          )
        rescue StandardError, ScriptError
          # swallow
        ensure
          @metrics_in_callback.delete(tid)
        end
      end
    end
  end
end
