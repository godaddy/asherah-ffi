package com.godaddy.asherah.jni;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;

/**
 * Unit tests for {@link NativeLoader} platform detection. Extraction is
 * exercised end-to-end by every test that loads the JNI library — this
 * file pins the RID-detection contract.
 */
class NativeLoaderTest {

  @Test
  void detectRidLinuxGlibcX64() {
    assertEquals("linux-x86_64", NativeLoader.detectRid("Linux", "amd64", false));
    assertEquals("linux-x86_64", NativeLoader.detectRid("Linux", "x86_64", false));
  }

  @Test
  void detectRidLinuxGlibcArm64() {
    assertEquals("linux-aarch64", NativeLoader.detectRid("Linux", "aarch64", false));
    assertEquals("linux-aarch64", NativeLoader.detectRid("Linux", "arm64", false));
  }

  @Test
  void detectRidLinuxMuslX64() {
    assertEquals("linux-musl-x86_64", NativeLoader.detectRid("Linux", "amd64", true));
  }

  @Test
  void detectRidLinuxMuslArm64() {
    assertEquals("linux-musl-aarch64", NativeLoader.detectRid("Linux", "aarch64", true));
  }

  @Test
  void detectRidMacOs() {
    assertEquals("darwin-x86_64", NativeLoader.detectRid("Mac OS X", "x86_64", false));
    assertEquals("darwin-aarch64", NativeLoader.detectRid("Darwin", "arm64", false));
    // musl flag is meaningless on macOS but should not break detection
    assertEquals("darwin-aarch64", NativeLoader.detectRid("Mac OS X", "aarch64", true));
  }

  @Test
  void detectRidWindows() {
    assertEquals("windows-x86_64", NativeLoader.detectRid("Windows 11", "amd64", false));
    assertEquals("windows-aarch64", NativeLoader.detectRid("Windows Server 2022", "aarch64", false));
  }

  @Test
  void detectRidUnknownOsReturnsNull() {
    assertNull(NativeLoader.detectRid("Plan 9", "amd64", false));
  }

  @Test
  void detectRidUnknownArchReturnsNull() {
    assertNull(NativeLoader.detectRid("Linux", "riscv64", false));
  }

  @Test
  void detectRidIsCaseInsensitive() {
    assertEquals("linux-x86_64", NativeLoader.detectRid("LINUX", "X86_64", false));
    assertEquals("windows-aarch64", NativeLoader.detectRid("Windows", "ARM64", false));
  }

  @Test
  void detectRidLiveSystemReturnsSomething() {
    // On every platform we publish to (linux/macos/windows × x64/arm64),
    // detectRid() with live properties must produce a non-null RID. If
    // CI ever runs on an unsupported OS this would fail loudly.
    String rid = NativeLoader.detectRid();
    assertNotNull(rid, "detectRid() returned null on supported platform");
    assertTrue(
        rid.startsWith("linux-") || rid.startsWith("darwin-") || rid.startsWith("windows-"),
        "Unexpected RID: " + rid);
  }

  @Test
  @DisabledOnOs(OS.WINDOWS) // POSIX permission set is part of the contract we test
  void extractFromResourcesWritesContentAddressedFile() throws IOException {
    // Stage a stub resource for the current platform RID by placing
    // bytes on the test classpath at native/<rid>/<libname>, then call
    // the package-private extraction helper directly. We cannot rely on
    // asherah.java.nativeLibraryPath being unset (the pom sets it for
    // surefire), so we exercise extraction by calling the helper itself.
    String rid = NativeLoader.detectRid();
    assertNotNull(rid);
    String libName = System.mapLibraryName("asherah_java");

    Path testClasses = Paths.get(
        NativeLoaderTest.class.getProtectionDomain().getCodeSource().getLocation().getPath());
    Path resourceDir = testClasses.resolve("native").resolve(rid);
    Files.createDirectories(resourceDir);
    Path resourceFile = resourceDir.resolve(libName);
    byte[] payload = ("asherah-stub-" + rid + "-" + System.nanoTime())
        .getBytes(StandardCharsets.UTF_8);
    Files.write(resourceFile, payload);

    try {
      Path extracted = NativeLoader.extractFromResources();
      assertNotNull(extracted, "extractFromResources returned null for live RID");
      assertTrue(Files.isRegularFile(extracted));
      assertArrayEquals(payload, Files.readAllBytes(extracted));
      // Cache directory name should be content-addressed (hex SHA-256 → 64 chars).
      String parentName = extracted.getParent().getFileName().toString();
      assertTrue(parentName.startsWith("asherah-jni-") && parentName.length() == "asherah-jni-".length() + 64,
          "Cache dir name not content-addressed: " + parentName);

      // Second extraction must reuse the same path (idempotent / dedup).
      Path again = NativeLoader.extractFromResources();
      assertEquals(extracted, again);
    } finally {
      Files.deleteIfExists(resourceFile);
    }
  }
}
