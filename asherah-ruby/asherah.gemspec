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

  spec.files = Dir["lib/**/*.rb", "LICENSE", "README.md"]
  spec.require_paths = ["lib"]

  spec.add_dependency "ffi", "~> 1.15"
end
