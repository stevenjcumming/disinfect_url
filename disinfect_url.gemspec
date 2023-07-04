# frozen_string_literal: true

require_relative "lib/disinfect_url/version"

Gem::Specification.new do |spec|
  spec.name = "disinfect_url"
  spec.version = DisinfectUrl::VERSION
  spec.authors = ["stevenjcumming"]

  spec.summary = "A gem to sanitize URLs or HTML"
  spec.description = "A gem to sanitize URLs or HTML href attributes within <a> tags to help prevent XSS attacks."
  spec.homepage = "https://github.com/stevenjcumming/disinfect_url"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 2.4.0"

  spec.metadata = {
    "homepage_uri" => "https://github.com/stevenjcumming/disinfect_url",
    "documentation_uri" => "https://rubydoc.info/github/stevenjcumming/disinfect_url",
    "changelog_uri" => "https://github.com/stevenjcumming/disinfect_url/blob/main/CHANGELOG.md",
    "source_code_uri" => "https://github.com/stevenjcumming/disinfect_url",
    "bug_tracker_uri" => "https://github.com/stevenjcumming/disinfect_url/issues"
  }

  spec.files = Dir["lib/**/*", "CHANGELOG.md", "LICENSE", "README.md"]
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "nokogiri", "~> 1.11"

  spec.add_development_dependency "bundler", "~> 2.0"
  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "rubocop", "~> 1.21"
  spec.add_development_dependency "rubocop-rspec", "~> 2.22"
  spec.add_development_dependency "yard", "~> 0.9.34"
end
