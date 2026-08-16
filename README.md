# Scryer — Ruby on Rails Security Auditor

Scryer is an all-in-one security auditing and static analysis tool for Ruby on Rails
applications — tells you what to fix first, across security, performance, dependencies, and code
quality. It answers a different question than a single-purpose linter does: not just "what's wrong," but
**what's actually worth fixing first**. It looks across security vulnerabilities, performance
problems, dependency risk, and code quality in one pass, ranks what it finds by severity, and
surfaces the handful of issues that matter most at the top of every report — with a
human-reviewable suggested fix for each one.

Brakeman is very good at finding security patterns in Rails apps — years of deep taint/data-flow
analysis that Scryer's heuristics don't try to match (see the honest comparison below). But a
security pattern match in isolation doesn't tell you whether it's the most urgent thing on your
plate this week, or the fifth-most: is that one SQL-injection-shaped call more or less pressing
than the vulnerable gem sitting in your `Gemfile.lock`, or the N+1 query burning production
database time right now? Answering that means looking at security, performance, dependencies, and
code quality *together*, not as four separate tool outputs to reconcile by hand. That's Scryer's
job:

```bash
gem install scryer
scryer
```

```
Scryer Audit — 236 files scanned
────────────────────────────────

Security Score: 10/100 (F)
Checks: 23/36 rules clean (63.9%)

Security               27 findings
Performance            10 findings
Code Quality          248 findings
Dependencies           24 findings
────────────────────────────────
Total                 309 findings

Top priorities:
  1. [critical] security — mass_assignment (app/helpers/api/v1/create_order_helper.rb:14)
  2. [critical] security — mass_assignment (app/helpers/api/v1/create_order_helper.rb:45)
  3. [critical] security — mass_assignment (app/helpers/api/v1/checkout/checkout_helper.rb:92)
  4. [critical] security — sql_injection (app/controllers/concerns/billing_helper.rb:12)
  5. [critical] security — mass_assignment (app/controllers/api/v1/orders_controller.rb:8)

OWASP Top 10 (2021) coverage:
  A01:2021-Broken Access Control: 16 findings
  A03:2021-Injection: 4 findings
  A08:2021-Software and Data Integrity Failures: 4 findings
  A02:2021-Cryptographic Failures: 1 finding
  A04:2021-Insecure Design: 1 finding
  A09:2021-Security Logging and Monitoring Failures: 1 finding

JSON report: tmp/scryer_report.json
HTML report: tmp/scryer_report.html
```

That's real output from a scan of a live 236-file Rails app (an internal production codebase we
call "acme-app" here — file/controller names above are anonymized, since we don't publish that
app's source; the finding counts, severities, rule IDs, and line numbers are exactly as scanned,
unedited) — not a mockup, and the harsh grade is real too (see
[Security score](docs/architecture.md#security-score) for what it does and doesn't mean). "Top priorities" is the same
severity ranking [`ReportRenderer#top_risks`](lib/scryer/report_renderer.rb) applies across *all*
categories — security, dependencies, performance, code quality — not just within each one; in the
HTML report it's at the top of the Findings section, ahead of the 309 individual findings
underneath it. See
[Scryer vs RuboCop vs Brakeman vs bundler-audit](docs/architecture.md#scryer-vs-rubocop-vs-brakeman-vs-bundler-audit)
below for exactly how this differs from what those tools do.

## Frequently asked questions

- **What does Scryer do?** Static security auditing and code analysis for Ruby/Rails codebases —
  security vulnerabilities, performance heuristics, dependency risk, and code-quality issues in one
  scan, ranked by severity across all four categories. See
  [What Scryer detects](docs/rules.md#what-scryer-detects).
- **Is it Rails-specific?** Most of the 31 security rules target Rails conventions specifically
  (controllers, `config/environments/*`, Active Storage, Action Cable, `params`), but the scanning
  engine itself only needs Ruby source — no Rails app or database required to run it. See
  [Designed for Ruby](docs/rules.md#designed-for-ruby).
- **What vulnerabilities does it detect?** SQL injection, mass assignment, SSRF, path traversal,
  IDOR, missing authorization, insecure JWT/CORS/session/cookie config, hardcoded secrets, XSS,
  weak crypto, unsafe deserialization, open redirects, and more — full list in
  [What Scryer detects](docs/rules.md#what-scryer-detects). Every finding carries a CWE ID and an OWASP Top 10
  (2021) category.
- **How is it different from Brakeman?** Brakeman does real taint/data-flow analysis for Rails
  security specifically — years of maturity Scryer doesn't try to match. Scryer's checks are
  heuristic pattern-matching, and its job is different: combining security, performance,
  dependency, and code-quality findings into one severity-ranked list, which none of those tools do
  on their own. See [Taint analysis vs. heuristic pattern
  matching](https://ramlaxmanyadav.github.io/scryer/taint-analysis-vs-heuristic-pattern-matching.html)
  and the [full comparison table](docs/architecture.md#scryer-vs-rubocop-vs-brakeman-vs-bundler-audit).
- **Is it actively maintained?** See [CHANGELOG.md](CHANGELOG.md) for release history and
  [lib/scryer/version.rb](lib/scryer/version.rb) for the current version.
- **Does it work in CI?** Yes — a bundled [GitHub Action](action.yml), SARIF output for GitHub Code
  Scanning, and a documented exit-code contract for gating any CI system. See
  [CI/CD integration](docs/usage.md#cicd-integration) and [Exit codes](docs/usage.md#exit-codes).
- **What's the license?** MIT. See [License](#license).
- **How do I install it?** `gem install scryer`, or add `gem "scryer", group: :development` to your
  `Gemfile`. See [Install](docs/usage.md#install).


## Documentation

This README covers the pitch, the FAQ, and licensing. Everything else lives in focused pages —
each one longer-form than a single section here, cross-linked from wherever it's relevant:

- [**Usage & Configuration**](docs/usage.md) — Install, running a scan, exit codes, CI/CD
  integration (GitHub Action + hand-written steps), what gets scanned, branch reporting, skipping
  rules, baseline mode.
- [**What Scryer Detects**](docs/rules.md) — the full rule list (security/performance/code
  quality/dependencies), example findings, report formats with real JSON/SARIF output, the
  dependency audit.
- [**Fix Mode & AI-Assisted Fixes**](docs/fix-mode.md) — `scryer verify`, `scryer fix`
  (mechanical, no-AI fixes plus the interactive accept/skip review), and optional AI-rewritten
  suggestions with any LLM you configure.
- [**Architecture, Performance & Security Model**](docs/architecture.md) — how it's built, real
  performance numbers, the security model, false-positive handling, the accuracy benchmark, and
  the full Scryer vs RuboCop vs Brakeman vs bundler-audit comparison.
- [**Rails Integration**](docs/rails-integration.md) — the runtime query/authorization watchers,
  the `scryer:install` generator, and testing Scryer's own results in your app's test suite.
- [**Contributing & Releasing**](docs/contributing.md) — how to add a new rule, and how this
  gem's own release process works.

Longer-form guides on the [docs site](https://ramlaxmanyadav.github.io/scryer/), each answering
one question in depth for search/AI-assistant discovery rather than restating the above:

- [What is a Rails security scanner?](https://ramlaxmanyadav.github.io/scryer/rails-security-scanner.html)
- [Taint analysis vs. heuristic pattern matching](https://ramlaxmanyadav.github.io/scryer/taint-analysis-vs-heuristic-pattern-matching.html)
- [Dependency security for Rails applications](https://ramlaxmanyadav.github.io/scryer/dependency-security.html)
- [Security code review checklist for Rails](https://ramlaxmanyadav.github.io/scryer/security-code-review-checklist.html)

Machine-readable overview for AI assistants/agents: [llms.txt](llms.txt) /
[llms-full.txt](llms-full.txt) (full concatenated docs, one fetch).

## License

MIT licensed.
