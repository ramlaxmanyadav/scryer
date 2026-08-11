require_relative "lib/scryer/version"

Gem::Specification.new do |spec|
  spec.name        = "scryer"
  spec.version     = Scryer::VERSION
  spec.authors     = ["Ram Laxman Yadav"]
  spec.summary     = "Ruby/Rails security & quality auditor — one command instead of Brakeman + bundler-audit + Reek."
  spec.description = <<~DESC
    One scan, one report: security, performance, duplicate-code, and dependency audits for Ruby
    and Rails — the ground Brakeman, bundler-audit, Reek, and custom glue scripts usually split
    between them, covered by a single `scryer` command. (Style/lint is RuboCop's job — Scryer
    doesn't touch that.)

    Detects SQL injection, mass assignment, hardcoded secrets, XSS, weak crypto, and more; N+1
    queries, missing pagination, and other performance heuristics; near-duplicate code; and
    known-vulnerable gems via a live OSV.dev dependency audit — on by default, every run.

    Every finding includes a human-reviewable suggested fix — never auto-applied, optionally
    rewritten against your actual code by any LLM you configure. Reports in JSON, self-contained
    HTML, or CSV. Zero runtime dependencies beyond Ruby's own stdlib.
  DESC
  # The docs site (below) is the project's actual front door — a real landing
  # page with the "why", the audit-box demo, and the comparison table — so it
  # gets top billing as spec.homepage. The GitHub repo is still one click
  # away via source_code_uri.
  spec.homepage              = "https://ramlaxmanyadav.github.io/scryer/"
  spec.license                  = "MIT"
  spec.required_ruby_version = ">= 2.7.0"

  # `homepage_uri` is deliberately omitted from metadata — it would just
  # duplicate spec.homepage above with the same URL, which RubyGems warns
  # about at build time (only one of the two gets shown on the gem page).
  spec.metadata = {
    "source_code_uri"       => "https://github.com/ramlaxmanyadav/scryer",
    "documentation_uri"     => "https://ramlaxmanyadav.github.io/scryer/",
    "changelog_uri"         => "https://github.com/ramlaxmanyadav/scryer/blob/main/CHANGELOG.md",
    "bug_tracker_uri"       => "https://github.com/ramlaxmanyadav/scryer/issues",
    "rubygems_mfa_required" => "true"
  }

  spec.files = Dir.glob("{lib,exe}/**/*") + %w[README.md CHANGELOG.md LICENSE.txt]
  spec.bindir = "exe"
  spec.executables = ["scryer"]
  spec.require_paths = ["lib"]

  # Deliberately zero runtime dependencies beyond Ruby's own stdlib (ripper,
  # json, digest, securerandom, set). The scanning engine doesn't need Rails
  # loaded to run; only the Railtie/generator paths are Rails-specific, and
  # those are conditionally loaded only inside a Rails app (see lib/scryer.rb).

  spec.add_development_dependency "rake", "~> 13.0"
end
