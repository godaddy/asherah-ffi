# frozen_string_literal: true

require "mkmf"

# Create a no-op Makefile (we don't compile C; we download a prebuilt binary)
create_makefile("asherah/asherah")

require_relative "fetch_native"
AsherahFetchNative.download
