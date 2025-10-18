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

### Current Hardcoded Assumptions

The CI workflow currently assumes x86_64 as the native architecture and cross-compiles to aarch64:
- Job names: `core-x86_64`, `package-x86_64`, `core-arm64`, `package-arm64`
- Artifact paths: `artifacts/x86_64`, `artifacts/aarch64`
- Cache keys: `-x86_64-`, `-arm64-`
- Manylinux containers: `manylinux_2_28_x86_64` for native, cross-compilers for aarch64

**Future Work**: The workflow could be made bidirectional by:
1. Detecting host architecture (`uname -m`)
2. Setting native=x86_64 cross=aarch64 (or vice versa)
3. Using variables throughout instead of hardcoded values
4. This would allow the same workflow to run on ARM64 laptops/runners
