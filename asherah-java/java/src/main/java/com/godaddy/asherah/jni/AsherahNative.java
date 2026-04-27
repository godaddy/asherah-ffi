package com.godaddy.asherah.jni;

final class AsherahNative {
  static {
    NativeLoader.load();
  }

  private AsherahNative() {}

  static native long factoryFromEnv();

  static native long factoryFromJson(String configJson);

  static native void closeFactory(long factoryHandle);

  static native void freeFactory(long factoryHandle);

  static native void setEnv(String envJson);

  static native long getSession(long factoryHandle, String partitionId);

  static native void closeSession(long sessionHandle);

  static native void freeSession(long sessionHandle);

  static native byte[] encrypt(long sessionHandle, byte[] plaintext);

  static native byte[] decrypt(long sessionHandle, byte[] ciphertextJson);

  static native void encryptAsync(long sessionHandle, byte[] plaintext,
      java.util.concurrent.CompletableFuture<byte[]> future);

  static native void decryptAsync(long sessionHandle, byte[] ciphertextJson,
      java.util.concurrent.CompletableFuture<byte[]> future);

  static native void setLogHook(AsherahLogHook callback);

  static native void clearLogHook();

  static native void setMetricsHook(AsherahMetricsHook callback);

  static native void clearMetricsHook();
}
