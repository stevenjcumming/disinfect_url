# frozen_string_literal: true

require "nokogiri"
require "disinfect_url"

# A class responsible for sanitizing HTML by cleaning up URLs within <a> tags.
# Not recommended to be used directly
module DisinfectUrl
  class HTMLSanitizer
    class << self
      # Sanitizes the given HTML by cleaning up URLs in href attributes within <a> tags.
      #
      # @param html [String] The HTML to sanitize.
      # @return [String] The sanitized HTML.
      def sanitize(html)
        return nil if html.nil? || html.to_s.strip.empty?

        fragment = Nokogiri::HTML.fragment(html)

        fragment.css("a").each do |link|
          link["href"] = DisinfectUrl::URLSanitizer.sanitize(link["href"])
        end

        fragment.to_html
      end
    end
  end
end
