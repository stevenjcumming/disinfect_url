# frozen_string_literal: true

require_relative "disinfect_url/version"
require_relative "disinfect_url/html_sanitizer"
require_relative "disinfect_url/url_sanitizer"

# Sanitizes a URL or an HTML string depending on the input.
module DisinfectUrl
  class << self
    # If the input is a URL (a string), it sanitizes the URL by removing
    # potentially dangerous elements and characters.
    #
    # If the input is an HTML string (a string), it sanitizes the URLs within
    # <a> tags by removing potentially dangerous elements and attributes.
    #
    # @param input [String] The URL or HTML string to be sanitized.
    # @return [String, nil] The sanitized URL or HTML string, or nil if the input is not a String.
    def sanitize(input)
      return unless input.is_a?(String)

      HTMLSanitizer.sanitize(URLSanitizer.sanitize(input))
    end
  end
end
