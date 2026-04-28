# frozen_string_literal: true

module Asherah
  # Base error class. Also serves as a namespace for specific error types
  # compatible with the canonical godaddy/asherah-ruby gem.
  class Error < StandardError
    ConfigError = Class.new(self)
    NotInitialized = Class.new(self)
    AlreadyInitialized = Class.new(self)
    GetSessionFailed = Class.new(self)
    EncryptFailed = Class.new(self)
    DecryptFailed = Class.new(self)
    BadConfig = Class.new(self)
    Timeout = Class.new(self)
  end
end
