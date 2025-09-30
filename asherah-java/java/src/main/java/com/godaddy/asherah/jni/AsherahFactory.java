package com.godaddy.asherah.jni;

import java.lang.ref.Cleaner;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

public final class AsherahFactory implements AutoCloseable {
  private static final Cleaner CLEANER = Cleaner.create();

  private final AtomicBoolean closed = new AtomicBoolean(false);
  private final FactoryCleanup cleanup;
  private final Cleaner.Cleanable cleanable;

  AsherahFactory(long handle) {
    if (handle == 0) {
      throw new IllegalStateException("Native factory handle is null");
    }
    this.cleanup = new FactoryCleanup(handle);
    this.cleanable = CLEANER.register(this, cleanup);
  }

  public AsherahSession getSession(String partitionId) {
    ensureOpen();
    Objects.requireNonNull(partitionId, "partitionId");
    final long sessionHandle = AsherahNative.getSession(cleanup.peek(), partitionId);
    if (sessionHandle == 0) {
      throw new IllegalStateException("Native session handle is null");
    }
    return new AsherahSession(sessionHandle);
  }

  @Override
  public synchronized void close() {
    if (closed.getAndSet(true)) {
      return;
    }
    final long handle = cleanup.take();
    if (handle == 0) {
      return;
    }
    try {
      AsherahNative.closeFactory(handle);
    } finally {
      AsherahNative.freeFactory(handle);
      cleanable.clean();
    }
  }

  private void ensureOpen() {
    if (closed.get()) {
      throw new IllegalStateException("Factory has been closed");
    }
  }

  private static final class FactoryCleanup implements Runnable {
    private final Object lock = new Object();
    private long handle;

    FactoryCleanup(long handle) {
      this.handle = handle;
    }

    long take() {
      synchronized (lock) {
        final long value = handle;
        handle = 0;
        return value;
      }
    }

    long peek() {
      synchronized (lock) {
        return handle;
      }
    }

    @Override
    public void run() {
      final long value = take();
      if (value != 0) {
        AsherahNative.freeFactory(value);
      }
    }
  }
}
