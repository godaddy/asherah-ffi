# Build Rules

## Rust Compilation

**NEVER compile Rust code under QEMU emulation or any other emulation.**

All Rust builds must be either:
1. Native compilation on the target architecture
2. Cross-compilation from a native host

Emulated builds are unacceptably slow (60-90 minutes vs 5-10 minutes) and are forbidden.

### Examples

❌ **WRONG**: `docker run --platform linux/arm64` on x86_64 (runs under QEMU)
❌ **WRONG**: Building in ARM64 container on x86_64 host
❌ **WRONG**: `cargo build` inside emulated environment

✅ **CORRECT**: Cross-compile from x86_64 to aarch64 with proper toolchain
✅ **CORRECT**: Native build on actual ARM64 hardware
✅ **CORRECT**: Using manylinux_2_28_x86_64 container with aarch64 cross-compiler

### CI Implementation

- Use manylinux_2_28 containers for glibc 2.28 compatibility
- Install cross-compile toolchains (gcc-aarch64-linux-gnu, etc.)
- Set proper environment variables for cross-compilation
- Trust pre-built artifacts from earlier pipeline stages
