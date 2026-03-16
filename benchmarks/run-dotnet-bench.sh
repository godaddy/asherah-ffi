#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
NEWMETASTORE_DIR="${NEWMETASTORE_DIR:-/tmp/asherah-newmetastore}"

# Ensure native FFI library path is set
if [ -z "${ASHERAH_DOTNET_NATIVE:-}" ]; then
    if [ -f "$ROOT_DIR/target/release/libasherah_ffi.dylib" ] || [ -f "$ROOT_DIR/target/release/libasherah_ffi.so" ]; then
        export ASHERAH_DOTNET_NATIVE="$ROOT_DIR/target/release"
    else
        echo "Error: ASHERAH_DOTNET_NATIVE not set and no release build found."
        echo "Run: cargo build --release -p asherah-ffi"
        exit 1
    fi
fi

# Clone new-metastore if not present
if [ ! -d "$NEWMETASTORE_DIR/csharp" ]; then
    echo "Cloning chief-micco/asherah new-metastore branch..."
    git clone --branch new-metastore --depth 1 https://github.com/chief-micco/asherah.git "$NEWMETASTORE_DIR"

    # Fix missing SecureMemory references in upstream
    sed -i.bak '/<PackageReference Include="App.Metrics"/a\
    <PackageReference Include="GoDaddy.Asherah.SecureMemory" Version="0.5.0" />' \
        "$NEWMETASTORE_DIR/csharp/AppEncryption/AppEncryption/AppEncryption.csproj"

    sed -i.bak '/<ItemGroup Label="Project References">/i\
    <ItemGroup Label="Package References">\
        <PackageReference Include="GoDaddy.Asherah.SecureMemory" Version="0.5.0" />\
    </ItemGroup>' \
        "$NEWMETASTORE_DIR/csharp/AppEncryption/AppEncryption.PlugIns.Testing/AppEncryption.PlugIns.Testing.csproj"

    rm -f "$NEWMETASTORE_DIR"/csharp/AppEncryption/AppEncryption/AppEncryption.csproj.bak \
          "$NEWMETASTORE_DIR"/csharp/AppEncryption/AppEncryption.PlugIns.Testing/AppEncryption.PlugIns.Testing.csproj.bak
fi

echo ""
echo "Running canonical v0.2.10 vs Rust FFI benchmark..."
echo ""
dotnet run --project "$ROOT_DIR/benchmarks/dotnet-bench" -c Release

echo ""
echo "Running new-metastore benchmark..."
echo ""
dotnet run --project "$ROOT_DIR/benchmarks/dotnet-bench-newmetastore" -c Release
