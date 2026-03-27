# frozen_string_literal: true

require "open-uri"
require "fileutils"
require "digest"
require "rbconfig"

# Downloads the prebuilt native library for the current platform from
# GitHub Releases during `gem install` (fallback gem only — platform gems
# ship the binary directly and never run this).
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

  class << self
    def download
      asset_name, local_name = resolve_platform
      dest = File.join(NATIVE_DIR, local_name)

      if File.exist?(dest)
        puts "#{dest} already exists, skipping download"
        return
      end

      version = resolve_version
      url = "https://github.com/#{REPO}/releases/download/#{version}/#{asset_name}"

      puts "Downloading native library: #{url}"
      content = download_with_retry(url)

      # Verify we got a reasonable binary (not an HTML error page)
      if content.bytesize < 1024
        abort "ERROR: Downloaded file is too small (#{content.bytesize} bytes) — likely a 404 or error page"
      end

      # Verify SHA256 against checksums from the release (if available)
      verify_checksum(content, asset_name, version)

      FileUtils.mkdir_p(NATIVE_DIR)
      File.binwrite(dest, content)
      File.chmod(0o755, dest) unless Gem.win_platform?
      puts "Installed native library: #{dest} (#{content.bytesize} bytes)"
    end

    private

    def resolve_platform
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

      key = [os, cpu]
      result = PLATFORM_MAP[key]
      abort "ERROR: Unsupported platform #{os}-#{cpu} (#{RUBY_PLATFORM})" unless result
      result
    end

    def resolve_version
      # The native binary version tracks asherah-ffi releases (v0.6.x), not the
      # gem version (0.9.x which tracks the canonical asherah-ruby gem).
      # Check for an explicit native version file first, then query GitHub API.
      native_version_file = File.join(ROOT_DIR, "NATIVE_VERSION")
      if File.exist?(native_version_file)
        tag = File.read(native_version_file).strip
        return tag unless tag.empty?
      end

      # Fall back: query GitHub API for latest release
      puts "Resolving latest release version from GitHub..."
      require "json"
      api_url = "https://api.github.com/repos/#{REPO}/releases/latest"
      response = URI.parse(api_url).open("Accept" => "application/vnd.github+json").read
      tag = JSON.parse(response)["tag_name"]
      abort "ERROR: Could not determine release version" if tag.nil? || tag.empty?
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
      # Try to download SHA256SUMS from the release
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
