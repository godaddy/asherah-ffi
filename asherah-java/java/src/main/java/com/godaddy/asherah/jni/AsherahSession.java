package com.godaddy.asherah.jni;

import java.lang.ref.Cleaner;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

public final class AsherahSession implements AutoCloseable {
  private static final Cleaner CLEANER = Cleaner.create();

  private final AtomicBoolean closed = new AtomicBoolean(false);
  private final SessionCleanup cleanup;
  private final Cleaner.Cleanable cleanable;

  AsherahSession(long handle) {
    if (handle == 0) {
      throw new IllegalStateException("Native session handle is null");
    }
    this.cleanup = new SessionCleanup(handle);
    this.cleanable = CLEANER.register(this, cleanup);
  }

  public byte[] encryptBytes(byte[] plaintext) {
    ensureOpen();
    Objects.requireNonNull(plaintext, "plaintext");
    final byte[] ciphertext = AsherahNative.encrypt(cleanup.peek(), plaintext);
    if (ciphertext == null) {
      throw new IllegalStateException("Native encrypt returned null");
    }
    return ciphertext;
  }

  public String encryptToJson(byte[] plaintext) {
    final byte[] ciphertext = encryptBytes(plaintext);
    return new String(ciphertext, StandardCharsets.UTF_8);
  }

  public String encryptString(String plaintext) {
    Objects.requireNonNull(plaintext, "plaintext");
    return encryptToJson(plaintext.getBytes(StandardCharsets.UTF_8));
  }

  public byte[] decryptBytes(byte[] ciphertextJson) {
    ensureOpen();
    Objects.requireNonNull(ciphertextJson, "ciphertextJson");
    final byte[] plaintext = AsherahNative.decrypt(cleanup.peek(), ciphertextJson);
    if (plaintext == null) {
      throw new IllegalStateException("Native decrypt returned null");
    }
    return plaintext;
  }

  public byte[] decryptFromJson(String ciphertextJson) {
    Objects.requireNonNull(ciphertextJson, "ciphertextJson");
    return decryptBytes(ciphertextJson.getBytes(StandardCharsets.UTF_8));
  }

  public String decryptString(String ciphertextJson) {
    Objects.requireNonNull(ciphertextJson, "ciphertextJson");
    byte[] plaintext = decryptFromJson(ciphertextJson);
    return new String(plaintext, StandardCharsets.UTF_8);
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
      AsherahNative.closeSession(handle);
    } finally {
      AsherahNative.freeSession(handle);
      cleanable.clean();
    }
  }

  private void ensureOpen() {
    if (closed.get()) {
      throw new IllegalStateException("Session has been closed");
    }
  }

  private static final class SessionCleanup implements Runnable {
    private final Object lock = new Object();
    private long handle;

    SessionCleanup(long handle) {
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
        AsherahNative.freeSession(value);
      }
    }
  }
}
