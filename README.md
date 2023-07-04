# DisinfectUrl

[![Gem Version](https://badge.fury.io/rb/disinfect_url.svg)](https://badge.fury.io/rb/disinfect_url)

This gem was _heavily_ influenced by Braintree's [sanitize-url](https://github.com/braintree/sanitize-url/tree/main)

## Installation

```ruby
gem 'disinfect_url'
```

## Usage

### Requirements

This gem requires Ruby 2.4+

### Basic Usage

Convert bad urls to "about:blank"

```ruby
DisinfectUrl.sanitize("https://example.com")
# => https://example.com

DisinfectUrl.sanitize("http://example.com")
# => http://example.com

DisinfectUrl.sanitize("www.example.com")
# => www.example.com

DisinfectUrl.sanitize("mailto:hello@example.com")
# => mailto:hello@example.com

DisinfectUrl.sanitize("&#104;&#116;&#116;&#112;&#115;&#0000058//&#101;&#120;&#97;&#109;&#112;&#108;&#101;&#46;&#99;&#111;&#109;")
# => https://example.com

DisinfectUrl.sanitize("javascript:alert(document.domain)")
DisinfectUrl.sanitize("jAvasCrIPT:alert(document.domain)")
DisinfectUrl.sanitize("JaVaScRiP%0at:alert(document.domain)")
# => about:blank

#HTML encoded javascript:alert('XSS')
DisinfectUrl.sanitize("&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041")
# => about:blank

# Works the same way for href attribute within <a> tags
DisinfectUrl.sanitize(%q(<a href="javascript:alert('attack')">Example</a>))
# => <a href="about:blank">Example</a>
```

### ActiveRecord Callbacks

```ruby
before_validation :disinfect_website_url
before_validation :disinfect_biography

private

  def disinfect_website_url
    self.website_url = DisinfectUrl.sanitize(self.website_url)
  end

  def disinfect_biography
    self.biography = DisinfectUrl.sanitize(self.biography)
  end
```

### Validation Note

This gem doesn't perform any validation for differentiating HTML vs URL. You may need to perform additional validation.

```ruby
  def disinfect_website_url
    self.website_url = DisinfectUrl.sanitize(%q(<a href="https://example.com">Example</a>))
  end
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/stevenjcumming/disinfect_url. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [code of conduct](https://github.com/stevenjcumming/disinfect_url/blob/main/CODE_OF_CONDUCT.md).

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the DisinfectUrl project's codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/stevenjcumming/disinfect_url/blob/main/CODE_OF_CONDUCT.md).
