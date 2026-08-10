require_relative "lib/scryer/version"

Gem::Specification.new do |spec|
  spec.name        = "scryer"
  spec.version     = Scryer::VERSION
  spec.authors     = ["Ram Laxman Yadav"]
  spec.summary     = "Static code analysis for Rails apps: security vulnerabilities, duplicate code, and performance heuristics."
  spec.description = <<~DESC
    Scans a Rails app's own source with Ruby's stdlib Ripper parser (no Rails/bundler needed to
    run the scan itself) and reports: security findings (SQL injection, mass assignment, command
    injection, hardcoded secrets, unsafe deserialization, XSS-prone unescaped HTML, CSRF gaps,
    weak crypto, open redirects), near-duplicate code (token-normalized similarity across
    methods), and performance heuristics (N+1 queries, missing pagination, inefficient per-record
    save loops, unbounded full-table iteration). Every finding includes a human-reviewable
    suggested fix — nothing is auto-applied. Writes a detailed report as JSON and/or
    self-contained HTML (tmp/scryer_report.{json,html}). Ships a `scryer` executable for
    running outside a Rails app too, e.g. `scryer -o report.json -o report.html`. Also includes a
    runtime query watcher (N+1 / unused-eager-load detection via ActiveRecord instrumentation,
    opt-in) and a dependency vulnerability + insecure-source audit against OSV.dev.
  DESC
  spec.homepage              = "https://github.com/ramlaxmanyadav/scryer"
  spec.license                  = "MIT"
  spec.required_ruby_version = ">= 2.7.0"

  spec.files = Dir.glob("{lib,exe}/**/*") + %w[README.md]
  spec.bindir = "exe"
  spec.executables = ["scryer"]
  spec.require_paths = ["lib"]

  # Deliberately zero runtime dependencies beyond Ruby's own stdlib (ripper,
  # json, digest, securerandom, set). The scanning engine doesn't need Rails
  # loaded to run; only the Railtie/generator paths are Rails-specific, and
  # those are conditionally loaded only inside a Rails app (see lib/scryer.rb).

  spec.add_development_dependency "rake", "~> 13.0"
end
