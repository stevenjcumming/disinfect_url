# frozen_string_literal: true

require "nokogiri"
require "disinfect_url"

RSpec.describe DisinfectUrl::HTMLSanitizer do
  describe ".sanitize" do
    it "returns nil if the HTML is nil" do
      expect(described_class.sanitize(nil)).to be_nil
    end

    it "returns nil if the HTML is empty" do
      expect(described_class.sanitize("")).to be_nil
    end

    it "returns nil if the HTML is blank" do
      expect(described_class.sanitize(" ")).to be_nil
    end

    it "handles HTML with no anchor tags" do
      html = "<p>This is a paragraph.</p>"
      sanitized_html = described_class.sanitize(html)
      expect(sanitized_html).to eq(html)
    end

    it "ignores non-href attributes" do
      html = '<a href="http://example.com" target="_blank">Example</a>'
      sanitized_html = described_class.sanitize(html)
      link = Nokogiri::HTML.parse(sanitized_html).css("a").first
      expect(link["href"]).to eq("http://example.com")
      expect(link["target"]).to eq("_blank")
    end

    it "does not alter the original HTML" do
      html = '<a href="http://example.com">Example</a>'
      described_class.sanitize(html)
      link = Nokogiri::HTML.parse(html).css("a").first
      expect(link["href"]).to eq("http://example.com")
    end

    context "when given dangerous urls in html" do
      it "sanitizes the href attribute of anchor tags" do
        html = %q(<a href="javascript:alert('XSS')">Example</a>)
        sanitized_html = described_class.sanitize(html)
        link = Nokogiri::HTML.parse(sanitized_html).css("a").first
        expect(link["href"]).to eq("about:blank")
      end

      it "sanitizes multiple anchor tags" do
        html = %q(<a href="http://example.com">Example 1</a><a href="javascript:alert('XSS')">Example 2</a>)
        sanitized_html = described_class.sanitize(html)
        links = Nokogiri::HTML.parse(sanitized_html).css("a")
        expect(links[0]["href"]).to eq("http://example.com")
        expect(links[1]["href"]).to eq("about:blank")
      end

      it "sanitizes nested anchor tags" do
        html = %q(<div><a href="http://example.com">Example 1</a><div><a href="javascript:alert('XSS')">Example 2</a></div></div>)
        sanitized_html = described_class.sanitize(html)
        links = Nokogiri::HTML.parse(sanitized_html).css("a")
        expect(links[0]["href"]).to eq("http://example.com")
        expect(links[1]["href"]).to eq("about:blank")
      end
    end
  end
end
