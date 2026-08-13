require_relative "lib/scryer/version"

Gem::Specification.new do |spec|
  spec.name        = "scryer"
  spec.version     = Scryer::VERSION
  spec.authors     = ["Ram Laxman Yadav"]
  spec.summary     = "Ruby/Rails application security & risk auditor — tells you what to fix first."
  spec.description = <<~DESC
    Scryer scans a Ruby/Rails codebase for security vulnerabilities, performance problems,
    dependency risk, and code-quality issues, then ranks everything it finds by severity across
    all of those categories — so a scan ends with one answer to "what's most worth fixing," not
    four separate reports to reconcile by hand. (Style/lint is RuboCop's job — Scryer doesn't
    touch that, except one narrow check.)

    Detects SQL injection, mass assignment, SSRF, path traversal, IDOR, insecure JWT/CORS/session
    config, hardcoded secrets, XSS, weak crypto, and more; N+1 queries, missing pagination, and
    other performance heuristics; near-duplicate code; and known-vulnerable gems via a live
    OSV.dev dependency audit — on by default, every run.

    Every finding includes a human-reviewable suggested fix — never auto-applied, optionally
    rewritten against your actual code by any LLM you configure. Reports in JSON, self-contained
    HTML, CSV, or SARIF (for GitHub Code Scanning). Zero runtime dependencies beyond Ruby's own
    stdlib.
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
