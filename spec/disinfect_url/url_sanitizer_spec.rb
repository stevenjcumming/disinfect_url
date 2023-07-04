# frozen_string_literal: true

require "disinfect_url"
require "uri"

RSpec.describe DisinfectUrl::URLSanitizer do
  describe ".sanitize" do
    context "when URL is nil, empty, or blank" do
      it "returns nil if the URL is nil" do
        expect(described_class.sanitize(nil)).to be_nil
      end

      it "returns nil if the URL is empty" do
        expect(described_class.sanitize("")).to be_nil
      end

      it "returns nil if the URL is blank" do
        expect(described_class.sanitize(" ")).to be_nil
      end
    end

    context "when URLs are valid" do
      it "preserves http URLs with alphanumeric characters" do
        expect(described_class.sanitize("http://example.com/path/to:something")).to eq("http://example.com/path/to:something")
      end

      it "preserves http URLs with ports with alphanumeric characters" do
        expect(described_class.sanitize("http://example.com:4567/path/to:something")).to eq("http://example.com:4567/path/to:something")
      end

      it "preserves https URLs with alphanumeric characters" do
        expect(described_class.sanitize("https://example.com")).to eq("https://example.com")
      end

      it "preserves https URLs with ports with alphanumeric characters" do
        expect(described_class.sanitize("https://example.com:4567/path/to:something")).to eq("https://example.com:4567/path/to:something")
      end

      it "preserves relative-path reference URLs with alphanumeric characters" do
        expect(described_class.sanitize("./path/to/my.json")).to eq("./path/to/my.json")
      end

      it "preserves absolute-path reference URLs with alphanumeric characters" do
        expect(described_class.sanitize("/path/to/my.json")).to eq("/path/to/my.json")
      end

      it "preserves protocol-less network-path URLs with alphanumeric characters" do
        expect(described_class.sanitize("//google.com/robots.txt")).to eq("//google.com/robots.txt")
      end

      it "preserves protocol-less URLs with alphanumeric characters" do
        expect(described_class.sanitize("www.example.com")).to eq("www.example.com")
      end

      it "preserves deep-link URLs with alphanumeric characters" do
        expect(described_class.sanitize("com.example.demo://example")).to eq("com.example.demo://example")
      end

      it "preserves mailto URLs with alphanumeric characters" do
        expect(described_class.sanitize("mailto:test@example.com?subject=hello+world")).to eq("mailto:test@example.com?subject=hello+world")
      end

      it "preserves URLs with accented characters" do
        expect(described_class.sanitize("www.example.com/with-áccêntš")).to eq("www.example.com/with-áccêntš")
      end

      it "does not strip harmless unicode characters" do
        expect(described_class.sanitize("www.example.com/лот.рфшишкиü–")).to eq("www.example.com/лот.рфшишкиü–")
      end
    end

    context "when URL contains unwanted characters" do
      it "strips out ctrl chars" do
        expect(described_class.sanitize("www.example.com/\u200D\u0000\u001F\x00\x1F\uFEFFfoo")).to eq("www.example.com/foo")
      end

      it "removes whitespace from URLs" do
        expect(described_class.sanitize("   http://example.com/path/to:something    ")).to eq("http://example.com/path/to:something")
      end

      it "removes newline entities from URLs" do
        expect(described_class.sanitize("https://example.com&NewLine;&NewLine;/something")).to eq("https://example.com/something")
      end
    end

    context "when URL contains HTML entities" do
      it "decodes HTML entities and replaces harmful characters with about:blank" do
        attack_vectors = [
          "&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041",
          "&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;",
          "&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29",
          "jav&#x09;ascript:alert('XSS');",
          " &#14; javascript:alert('XSS');",
          "javasc&Tab;ript: alert('XSS');",
        ]
      
        attack_vectors.each do |vector|
          expect(described_class.sanitize(vector)).to eq("about:blank")
        end
      end

      it "decodes HTML entities and preserves http URLs with alphanumeric characters" do 
        expect(described_class.sanitize("&#104;&#116;&#116;&#112;&#115;&#0000058//&#101;&#120;&#97;&#109;&#112;&#108;&#101;&#46;&#99;&#111;&#109;/&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041")).to eq("https://example.com/javascript:alert('XSS')")
      end
    end

    context "when protocols are invalid" do
      %w[javascript data vbscript].each do |protocol|
        it "replaces #{protocol} urls with about:blank" do
          expect(described_class.sanitize("#{protocol}:alert(document.domain)")).to eq("about:blank")
        end

        it "allows #{protocol} urls that start with a letter prefix" do
          expect(described_class.sanitize("not_#{protocol}:alert(document.domain)")).to eq("not_#{protocol}:alert(document.domain)")
        end

        it "disallows #{protocol} urls that start with non-\w characters as a suffix for the protocol" do
          expect(described_class.sanitize("&!*#{protocol}:alert(document.domain)")).to eq("about:blank")
        end

        it "disallows #{protocol} urls that use &colon; for the colon portion of the url" do
          expect(described_class.sanitize("#{protocol}&colon;alert(document.domain)")).to eq("about:blank")
          expect(described_class.sanitize("#{protocol}&COLON;alert(document.domain)")).to eq("about:blank")
        end

        it "disregards capitalization for #{protocol} urls" do
          mixed_capitalization_protocol = protocol.chars.map.with_index do |character, index|
            index.even? ? character.upcase : character
          end.join
          expect(described_class.sanitize("#{mixed_capitalization_protocol}:alert(document.domain)")).to eq("about:blank")
        end

        it "ignores invisible ctrl characters in #{protocol} urls" do
          protocol_with_control_characters = protocol.chars.map.with_index do |character, index|
            if index == 1
              "#{character}%EF%BB%BF%EF%BB%BF"
            else
              index == 2 ? "#{character}%e2%80%8b" : character
            end
          end.join
          expect(described_class.sanitize(URI.decode_www_form_component("#{protocol_with_control_characters}:alert(document.domain)"))).to eq("about:blank")
        end

        it "replaces #{protocol} urls with about:blank when url begins with %20" do
          expect(described_class.sanitize(URI.decode_www_form_component("%20%20%20%20#{protocol}:alert(document.domain)"))).to eq("about:blank")
        end

        it "replaces #{protocol} urls with about:blank when #{protocol} url begins with spaces" do
          expect(described_class.sanitize("    #{protocol}:alert(document.domain)")).to eq("about:blank")
        end

        it "does not replace #{protocol}: if it is not in the scheme of the URL" do
          expect(described_class.sanitize("http://example.com##{protocol}:foo")).to eq("http://example.com##{protocol}:foo")
        end
      end
    end
  end
end
