package com.godaddy.asherah.jni;

import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.atomic.AtomicBoolean;

final class NativeLoader {
  private static final AtomicBoolean LOADED = new AtomicBoolean(false);

  private NativeLoader() {}

  static void load() {
    if (LOADED.get()) {
      return;
    }
    synchronized (NativeLoader.class) {
      if (LOADED.get()) {
        return;
      }
      loadImpl();
      LOADED.set(true);
    }
  }

  private static void loadImpl() {
    final String explicit = explicitLibraryPath();
    if (explicit != null && !explicit.trim().isEmpty()) {
      final Path candidate;
      try {
        Path path = Paths.get(explicit);
        if (Files.isDirectory(path)) {
          path = path.resolve(System.mapLibraryName("asherah_java"));
        }
        candidate = path.toAbsolutePath().normalize();
      } catch (InvalidPathException e) {
        throw new IllegalStateException("Invalid Asherah native library path: " + explicit, e);
      }

      if (!Files.exists(candidate)) {
        throw new IllegalStateException("Asherah native library not found at " + candidate);
      }

      try {
        System.load(candidate.toString());
      } catch (UnsatisfiedLinkError e) {
        throw new IllegalStateException("Failed to load Asherah native library from " + candidate, e);
      }
      return;
    }
    try {
      System.loadLibrary("asherah_java");
    } catch (UnsatisfiedLinkError e) {
      throw new IllegalStateException("Failed to load Asherah native library via System.loadLibrary", e);
    }
  }

  private static String explicitLibraryPath() {
    String configured = System.getProperty("asherah.java.nativeLibraryPath");
    if (configured != null && !configured.trim().isEmpty()) {
      return configured;
    }
    configured = System.getenv("ASHERAH_JAVA_NATIVE");
    if (configured != null && !configured.trim().isEmpty()) {
      return configured;
    }
    return null;
  }
}
