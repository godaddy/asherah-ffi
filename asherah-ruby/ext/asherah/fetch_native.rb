# frozen_string_literal: true

require "open-uri"
require "fileutils"
require "digest"
require "rbconfig"

# Acquires the prebuilt native library for the current platform.
# Tries in order:
# 1. Already exists (previous install or platform gem)
# 2. Build from source if in a git checkout with cargo available
# 3. Read NATIVE_VERSION from published fallback gem → download that release
# 4. Query GitHub API for latest release → download
module AsherahFetchNative
  REPO = "godaddy/asherah-ffi"
  MAX_ATTEMPTS = 3
  RETRY_DELAY = 5 # seconds, doubles each retry
  ROOT_DIR = File.expand_path("../../", __dir__)
  NATIVE_DIR = File.join(ROOT_DIR, "lib", "asherah", "native")

  # Map Ruby platform identifiers to our release asset names.
  # Keys: [os, cpu] from RbConfig. Values: [asset_name, local_name].
  PLATFORM_MAP = {
    ["linux", "x86_64"]   => ["libasherah-x64.so",       "libasherah_ffi.so"],
    ["linux", "aarch64"]  => ["libasherah-arm64.so",      "libasherah_ffi.so"],
    ["darwin", "x86_64"]  => ["libasherah-x64.dylib",     "libasherah_ffi.dylib"],
    ["darwin", "arm64"]   => ["libasherah-arm64.dylib",   "libasherah_ffi.dylib"],
    ["mingw", "x86_64"]   => ["libasherah-x64.dll",       "asherah_ffi.dll"],
    ["mingw", "aarch64"]  => ["libasherah-arm64.dll",      "asherah_ffi.dll"],
  }.freeze

  # Map [os, cpu] to the Rust library filename produced by cargo build.
  CARGO_LIB_NAME = {
    ["linux", "x86_64"]   => "libasherah_ffi.so",
    ["linux", "aarch64"]  => "libasherah_ffi.so",
    ["darwin", "x86_64"]  => "libasherah_ffi.dylib",
    ["darwin", "arm64"]   => "libasherah_ffi.dylib",
    ["mingw", "x86_64"]   => "asherah_ffi.dll",
    ["mingw", "aarch64"]  => "asherah_ffi.dll",
  }.freeze

  class << self
    def download
      _asset_name, local_name = resolve_platform
      dest = File.join(NATIVE_DIR, local_name)

      if File.exist?(dest)
        puts "#{dest} already exists, skipping"
        return
      end

      # Try building from source (git checkout with cargo)
      if try_build_from_source(dest)
        return
      end

      # Fall back to downloading a prebuilt binary
      download_prebuilt(dest)
    end

    private

    def try_build_from_source(dest)
      workspace_root = File.expand_path("..", ROOT_DIR)
      cargo_toml = File.join(workspace_root, "Cargo.toml")

      return false unless File.exist?(cargo_toml)

      cargo = find_cargo
      return false unless cargo

      puts "Building native library from source (this may take a minute)..."
      result = system(cargo, "build", "-p", "asherah-ffi", "--release",
                       chdir: workspace_root,
                       out: $stdout, err: $stderr)

      unless result
        puts "WARNING: cargo build failed, falling back to download"
        return false
      end

      os, cpu = resolve_os_cpu
      lib_name = CARGO_LIB_NAME[[os, cpu]]
      built = File.join(workspace_root, "target", "release", lib_name)

      unless File.exist?(built)
        puts "WARNING: Expected #{built} after cargo build, falling back to download"
        return false
      end

      FileUtils.mkdir_p(NATIVE_DIR)
      FileUtils.cp(built, dest)
      File.chmod(0o755, dest) unless Gem.win_platform?
      puts "Built and installed native library: #{dest} (#{File.size(dest)} bytes)"
      true
    end

    def find_cargo
      # Check PATH
      cargo = ENV["CARGO"] || "cargo"
      return cargo if system(cargo, "--version", out: File::NULL, err: File::NULL)

      # Check common install locations
      home = ENV["HOME"] || ENV["USERPROFILE"]
      if home
        rustup_cargo = File.join(home, ".cargo", "bin", "cargo")
        return rustup_cargo if File.executable?(rustup_cargo)
      end

      # Install Rust via rustup if not found
      return nil if Gem.win_platform? # rustup -y doesn't work unattended on Windows

      puts "Rust not found. Installing via rustup..."
      install_ok = system("curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal",
                          out: $stdout, err: $stderr)
      unless install_ok
        puts "WARNING: rustup install failed"
        return nil
      end

      if home
        installed = File.join(home, ".cargo", "bin", "cargo")
        return installed if File.executable?(installed)
      end

      nil
    end

    def download_prebuilt(dest)
      asset_name, _local_name = resolve_platform
      version = resolve_version
      url = "https://github.com/#{REPO}/releases/download/#{version}/#{asset_name}"

      puts "Downloading native library: #{url}"
      content = download_with_retry(url)

      if content.bytesize < 1024
        abort "ERROR: Downloaded file is too small (#{content.bytesize} bytes) — likely a 404 or error page"
      end

      verify_checksum(content, asset_name, version)

      FileUtils.mkdir_p(NATIVE_DIR)
      File.binwrite(dest, content)
      File.chmod(0o755, dest) unless Gem.win_platform?
      puts "Installed native library: #{dest} (#{content.bytesize} bytes)"
    end

    def resolve_platform
      os, cpu = resolve_os_cpu
      key = [os, cpu]
      result = PLATFORM_MAP[key]
      abort "ERROR: Unsupported platform #{os}-#{cpu} (#{RUBY_PLATFORM})" unless result
      result
    end

    def resolve_os_cpu
      host_os = RbConfig::CONFIG["host_os"]
      host_cpu = RbConfig::CONFIG["host_cpu"]

      os = case host_os
           when /linux/          then "linux"
           when /darwin/         then "darwin"
           when /mswin|mingw/    then "mingw"
           else                       host_os
           end

      cpu = case host_cpu
            when /x86_64|x64|amd64/   then "x86_64"
            when /aarch64|arm64/       then os == "darwin" ? "arm64" : "aarch64"
            else                            host_cpu
            end

      [os, cpu]
    end

    def resolve_version
      # The native binary version tracks asherah-ffi releases (v0.6.x), not the
      # gem version (0.9.x which tracks the canonical asherah-ruby gem).
      # NATIVE_VERSION is stamped into published fallback gems by the publish
      # workflow. For git-sourced installs it won't exist, so we fall through
      # to the GitHub API.
      native_version_file = File.join(ROOT_DIR, "NATIVE_VERSION")
      if File.exist?(native_version_file)
        tag = File.read(native_version_file).strip
        unless tag.empty?
          puts "Using native version: #{tag}"
          return tag
        end
      end

      # Fallback: query GitHub API for latest release
      puts "NATIVE_VERSION not found, resolving latest release from GitHub..."
      require "json"
      api_url = "https://api.github.com/repos/#{REPO}/releases/latest"
      response = URI.parse(api_url).open("Accept" => "application/vnd.github+json").read
      tag = JSON.parse(response)["tag_name"]
      abort "ERROR: Could not determine release version" if tag.nil? || tag.empty?
      puts "Using release: #{tag}"
      tag
    end

    def download_with_retry(url)
      attempt = 0
      delay = RETRY_DELAY

      loop do
        attempt += 1
        begin
          return URI.parse(url).open(
            "Accept" => "application/octet-stream",
            redirect: true,
            read_timeout: 60,
            open_timeout: 30
          ).read
        rescue OpenURI::HTTPError => e
          if e.message.include?("404")
            abort "ERROR: Release asset not found at #{url}\n" \
                  "       Ensure the release exists and includes this platform's binary."
          end
          raise unless attempt < MAX_ATTEMPTS

          puts "Download failed (attempt #{attempt}/#{MAX_ATTEMPTS}): #{e.message}"
          puts "Retrying in #{delay}s..."
          sleep delay
          delay *= 2
        rescue Net::OpenTimeout, Net::ReadTimeout, Errno::ECONNRESET, Errno::ECONNREFUSED => e
          raise unless attempt < MAX_ATTEMPTS

          puts "Download failed (attempt #{attempt}/#{MAX_ATTEMPTS}): #{e.class}: #{e.message}"
          puts "Retrying in #{delay}s..."
          sleep delay
          delay *= 2
        end
      end
    end

    def verify_checksum(content, asset_name, version)
      sums_url = "https://github.com/#{REPO}/releases/download/#{version}/SHA256SUMS"
      begin
        sums = URI.parse(sums_url).open(read_timeout: 15, open_timeout: 10).read
        expected = nil
        sums.each_line do |line|
          hash, name = line.strip.split(/\s+/, 2)
          if name == asset_name
            expected = hash
            break
          end
        end

        if expected
          actual = Digest::SHA256.hexdigest(content)
          if actual != expected
            abort "ERROR: SHA256 checksum mismatch for #{asset_name}\n" \
                  "  Expected: #{expected}\n" \
                  "  Actual:   #{actual}"
          end
          puts "SHA256 checksum verified: #{actual}"
        else
          puts "WARNING: No checksum found for #{asset_name} in SHA256SUMS"
        end
      rescue OpenURI::HTTPError, Net::OpenTimeout, Net::ReadTimeout => e
        puts "WARNING: Could not verify checksum (#{e.class}: #{e.message})"
      end
    end
  end
end
