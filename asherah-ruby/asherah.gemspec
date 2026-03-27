# frozen_string_literal: true

require_relative "lib/asherah/version"

Gem::Specification.new do |spec|
  spec.name = "asherah"
  spec.version = Asherah::VERSION
  spec.authors = ["GoDaddy"]
  spec.summary = "Asherah application-layer encryption for Ruby"
  spec.description = "Asherah application-layer encryption for Ruby, powered by the native Rust implementation."
  spec.homepage = "https://github.com/godaddy/asherah-ffi"
  spec.license = "Apache-2.0"
  spec.required_ruby_version = ">= 3.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["github_repo"] = "ssh://github.com/godaddy/asherah-ffi"
  spec.metadata["rubygems_mfa_required"] = "true"

  # Platform-specific gems include the precompiled native library.
  # Set ASHERAH_GEM_PLATFORM to build a platform gem (e.g. x86_64-linux, arm64-darwin).
  # Without it, the fallback "ruby" platform gem is built (requires ASHERAH_RUBY_NATIVE at runtime).
  gem_platform = ENV["ASHERAH_GEM_PLATFORM"]
  if gem_platform
    # Platform-specific gem: ships the precompiled native library directly.
    spec.platform = Gem::Platform.new(gem_platform)
    spec.files = Dir["lib/**/*.rb", "lib/asherah/native/libasherah_ffi.*", "lib/asherah/native/asherah_ffi.*", "LICENSE", "README.md"]
  else
    # Fallback gem: no binary bundled. Downloads the native library at install
    # time from GitHub Releases via ext/asherah/extconf.rb.
    # NATIVE_VERSION is stamped by the publish workflow (not in git).
    # Dir[] only matches if the file exists, so it's included in published
    # fallback gems but absent from development installs.
    spec.files = Dir["lib/**/*.rb", "ext/**/*.rb", "ext/**/*.c", "NATIVE_VERSION", "LICENSE", "README.md"]
    spec.extensions = ["ext/asherah/extconf.rb"]
  end

  spec.require_paths = ["lib"]

  spec.add_dependency "ffi", "~> 1.15"
end
