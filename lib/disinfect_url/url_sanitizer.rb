# frozen_string_literal: true

require "cgi"

# A class responsible for sanitizing URLs.
# Not recommended to be used directly
module DisinfectUrl
  class URLSanitizer
    INVALID_PROTOCOL_REGEX = /^([^\w]*)(javascript|data|vbscript)/im.freeze
    HTML_ENTITIES_REGEX = /&#(\w+)(?!\w|;)?/.freeze
    HTML_CTRL_ENTITY_REGEX = /&(newline|tab);/i.freeze
    CTRL_CHARACTERS_REGEX = /[\u0000-\u001F\u007F-\u009F\u2000-\u200D\uFEFF]/m.freeze
    URL_SCHEME_REGEX = /^.+(:|&colon;)/mi.freeze
    RELATIVE_FIRST_CHARACTERS = [".", "/"].freeze

    class << self
      # Sanitizes the given URL by removing invalid parts and characters.
      #
      # @param url [String] The URL to sanitize.
      # @return [String] The sanitized URL.
      def sanitize(url)
        return nil if url.nil? || url.to_s.strip.empty?

        sanitized_url = decode_html_characters(url || "")
                        .gsub(HTML_CTRL_ENTITY_REGEX, "")
                        .gsub(CTRL_CHARACTERS_REGEX, "")
                        .strip

        return "about:blank" if sanitized_url.empty?

        return sanitized_url if relative_url_without_protocol?(sanitized_url)

        url_scheme_parse_results = sanitized_url.match(URL_SCHEME_REGEX)

        return sanitized_url unless url_scheme_parse_results

        url_scheme = url_scheme_parse_results[0]

        return "about:blank" if INVALID_PROTOCOL_REGEX.match(url_scheme)

        sanitized_url
      end

      private

      # Checks if the URL is a relative URL without a protocol.
      #
      # @param url [String] The URL to check.
      # @return [Boolean] `true` if the URL is a relative URL without a protocol, `false` otherwise.
      def relative_url_without_protocol?(url)
        RELATIVE_FIRST_CHARACTERS.include?(url[0])
      end

      # Decodes HTML entities in the given string.
      #
      # @param str [String] The string to decode.
      # @return [String] The decoded string.
      def decode_html_characters(str)
        str = CGI.unescapeHTML(str)
        str.gsub(HTML_ENTITIES_REGEX) { |match| match[2..-1].to_i.chr }
      end
    end
  end
end
