package com.godaddy.asherah.jni;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

final class NativeLoader {
  private static final AtomicBoolean LOADED = new AtomicBoolean(false);
  private static final String EXTRACT_DIR_PROP = "asherah.java.nativeExtractDir";
  private static final String EXTRACT_DIR_ENV = "ASHERAH_JAVA_NATIVE_EXTRACT_DIR";

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
    // 1. Explicit override (system property or env var). Always wins.
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

    // 2. Extract bundled JAR resource for the detected platform.
    Throwable extractOrLoadError = null;
    StringBuilder attempted = new StringBuilder();
    for (Path baseDir : extractionBaseDirs()) {
      Path extracted = null;
      try {
        extracted = extractFromResources(baseDir);
      } catch (IOException | RuntimeException e) {
        extractOrLoadError = e;
      }
      if (extracted == null) {
        continue;
      }
      if (attempted.length() > 0) {
        attempted.append(", ");
      }
      attempted.append(extracted);
      try {
        System.load(extracted.toString());
        return;
      } catch (UnsatisfiedLinkError e) {
        extractOrLoadError = e;
        if (isPermissionStyleLoadFailure(e)) {
          // Common on SELinux/noexec mounts (for example /tmp on hardened RHEL).
          // Continue trying alternate extraction directories before falling back.
          continue;
        }
        throw new IllegalStateException(
            "Failed to load Asherah native library extracted from JAR at " + extracted, e);
      }
    }

    // 3. Fallback: java.library.path / System.loadLibrary.
    try {
      System.loadLibrary("asherah_java");
    } catch (UnsatisfiedLinkError e) {
      String msg = "Failed to load Asherah native library. Tried: bundled JAR resource"
          + (attempted.length() > 0 ? " at [" + attempted + "]" : "")
          + (extractOrLoadError != null ? " (" + extractOrLoadError.getMessage() + ")" : "")
          + ", java.library.path. Set ASHERAH_JAVA_NATIVE or "
          + "-Dasherah.java.nativeLibraryPath=<path> to override. "
          + "For SELinux/noexec environments, set "
          + "-D" + EXTRACT_DIR_PROP + "=<exec-allowed-dir>.";
      throw new IllegalStateException(msg, e);
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

  /**
   * Returns the runtime identifier folder name used inside the JAR
   * ({@code native/<rid>/<libname>}). Visible to tests via
   * package-private {@link #detectRid(String, String, boolean)}.
   */
  static String detectRid() {
    return detectRid(
        System.getProperty("os.name", ""),
        System.getProperty("os.arch", ""),
        isMusl());
  }

  static String detectRid(String osName, String osArch, boolean musl) {
    String os = osName.toLowerCase(Locale.ROOT);
    String archLower = osArch.toLowerCase(Locale.ROOT);
    String arch;
    if ("amd64".equals(archLower) || "x86_64".equals(archLower) || "x64".equals(archLower)) {
      arch = "x86_64";
    } else if ("aarch64".equals(archLower) || "arm64".equals(archLower)) {
      arch = "aarch64";
    } else {
      return null;
    }

    if (os.contains("linux")) {
      return (musl ? "linux-musl-" : "linux-") + arch;
    }
    if (os.contains("mac") || os.contains("darwin") || os.contains("os x")) {
      return "darwin-" + arch;
    }
    if (os.contains("windows")) {
      return "windows-" + arch;
    }
    return null;
  }

  /**
   * Detects musl libc by looking for the musl dynamic linker. Reliable
   * on Alpine and other musl-based distributions; cheaper and simpler
   * than parsing {@code ldd --version} output.
   */
  static boolean isMusl() {
    return Files.exists(Paths.get("/lib/ld-musl-x86_64.so.1"))
        || Files.exists(Paths.get("/lib/ld-musl-aarch64.so.1"));
  }

  /**
   * Extracts the appropriate {@code native/<rid>/<libname>} resource to a
   * stable, content-addressed path under {@code java.io.tmpdir} and
   * returns the path. Returns {@code null} if no resource matches the
   * current platform.
   *
   * <p>The cache directory name includes a SHA-256 of the resource bytes
   * so concurrent JVMs reuse the same file and version upgrades land in
   * a separate directory automatically.
   */
  static Path extractFromResources() throws IOException {
    return extractFromResources(Paths.get(System.getProperty("java.io.tmpdir")));
  }

  static Path extractFromResources(Path baseDir) throws IOException {
    String rid = detectRid();
    if (rid == null) {
      return null;
    }
    String libName = System.mapLibraryName("asherah_java");
    String resourcePath = "/native/" + rid + "/" + libName;

    byte[] contents;
    try (InputStream in = NativeLoader.class.getResourceAsStream(resourcePath)) {
      if (in == null) {
        return null;
      }
      contents = in.readAllBytes();
    }

    String hashHex = sha256Hex(contents);
    Path cacheDir = baseDir
        .resolve("asherah-jni-" + hashHex);
    Path target = cacheDir.resolve(libName);

    if (Files.isRegularFile(target) && Files.size(target) == contents.length) {
      return target;
    }

    Files.createDirectories(cacheDir);
    Path tmp = Files.createTempFile(cacheDir, libName + ".", ".tmp");
    boolean published = false;
    try {
      Files.write(tmp, contents);
      if (!System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("windows")) {
        try {
          Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString("rwxr-xr-x"));
        } catch (UnsupportedOperationException ignored) {
          // Non-POSIX FS — JVM will load anyway as long as the file is readable.
        }
      }
      try {
        Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE);
        published = true;
      } catch (FileAlreadyExistsException e) {
        // Another JVM published it first. Use the existing file rather than
        // replacing it, since something may already have it mmap'd.
      } catch (AtomicMoveNotSupportedException e) {
        try {
          Files.move(tmp, target);
          published = true;
        } catch (FileAlreadyExistsException ignored) {
          // Same race as above — fall through to use existing file.
        }
      }
    } finally {
      if (!published) {
        Files.deleteIfExists(tmp);
      }
    }
    return target;
  }

  private static String sha256Hex(byte[] data) {
    MessageDigest md;
    try {
      md = MessageDigest.getInstance("SHA-256");
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 not available", e);
    }
    byte[] hash = md.digest(data);
    StringBuilder sb = new StringBuilder(hash.length * 2);
    for (byte b : hash) {
      sb.append(Character.forDigit((b >>> 4) & 0xF, 16));
      sb.append(Character.forDigit(b & 0xF, 16));
    }
    return sb.toString();
  }
  static boolean isPermissionStyleLoadFailure(Throwable t) {
    String msg = t == null ? "" : String.valueOf(t.getMessage());
    String lower = msg.toLowerCase(Locale.ROOT);
    return lower.contains("permission denied")
        || lower.contains("operation not permitted")
        || lower.contains("failed to map segment from shared object")
        || lower.contains("cannot restore segment prot after reloc")
        || lower.contains("selinux");
  }

  static List<Path> extractionBaseDirs() {
    return extractionBaseDirs(
        firstNonBlank(System.getProperty(EXTRACT_DIR_PROP), System.getenv(EXTRACT_DIR_ENV)),
        System.getProperty("java.io.tmpdir"),
        System.getProperty("user.home"),
        System.getProperty("user.dir"));
  }

  static List<Path> extractionBaseDirs(
      String explicitExtractDir, String javaTmpDir, String userHome, String userDir) {
    LinkedHashSet<Path> ordered = new LinkedHashSet<>();
    addBaseDir(ordered, explicitExtractDir);
    addBaseDir(ordered, javaTmpDir);
    if (userHome != null && !userHome.isBlank()) {
      addBaseDir(ordered, Paths.get(userHome).resolve(".cache").resolve("asherah-jni").toString());
      addBaseDir(ordered, Paths.get(userHome).resolve(".asherah-jni").toString());
    }
    if (userDir != null && !userDir.isBlank()) {
      addBaseDir(ordered, Paths.get(userDir).resolve(".asherah-jni").toString());
    }
    return new ArrayList<>(ordered);
  }

  private static void addBaseDir(LinkedHashSet<Path> ordered, String rawPath) {
    if (rawPath == null || rawPath.isBlank()) {
      return;
    }
    try {
      ordered.add(Paths.get(rawPath).toAbsolutePath().normalize());
    } catch (InvalidPathException ignored) {
      // Invalid candidate path is ignored; other candidates still apply.
    }
  }

  private static String firstNonBlank(String a, String b) {
    if (a != null && !a.isBlank()) {
      return a;
    }
    if (b != null && !b.isBlank()) {
      return b;
    }
    return null;
  }
}
