# frozen_string_literal: true

require "disinfect_url"

RSpec.describe DisinfectUrl do
  describe ".sanitize" do
    context "when given a valid URL" do
      let(:url) { "https://example.com" }

      it "sanitizes the URL" do
        result = described_class.sanitize(url)
        expect(result).to eq(url)
      end
    end

    context "when given a non-string input" do
      let(:input) { 123 }

      it "returns nil" do
        result = described_class.sanitize(input)
        expect(result).to be_nil
      end
    end

    context "when given a dangerous URL" do
      let(:url) { 'javascript:alert("attack")' }

      it "sanitizes the URL" do
        result = described_class.sanitize(url)
        expect(result).to eq("about:blank")
      end
    end

    context "when given a valid HTML string with URLs in <a> tags" do
      let(:html) { '<p>Hello, <a href="https://example.com">World</a>!</p>' }
      let(:result) { '<p>Hello, <a href="https://example.com">World</a>!</p>' }

      it "sanitizes the URLs within <a> tags in the HTML string" do
        result = described_class.sanitize(html)
        expect(result).to eq(result)
      end
    end

    context "when given a valid HTML string without <a> tags" do
      let(:html) { "<p>Hello, World!</p>" }

      it "returns the same HTML string" do
        result = described_class.sanitize(html)
        expect(result).to eq(html)
      end
    end

    context "when given a dangerous HTML" do
      let(:html) { %q(<a href="javascript:alert('attack')">Example</a>) }

      it "sanitizes the URL" do
        result = described_class.sanitize(html)
        expect(result).to eq("<a href=\"about:blank\">Example</a>")
      end
    end
  end
end
