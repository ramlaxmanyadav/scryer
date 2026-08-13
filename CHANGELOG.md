# Changelog

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

- New `ReportRenderer#top_risks` — merges every severity-bearing finding from a scan (security,
  performance, code quality, and dependencies) into one list, sorted by severity first and
  category second, so a scan produces one ranked "what to fix first" answer instead of four
  separate category counts. Shown as a "Top priorities" list in the CLI/rake console summary
  (right after the finding-count box) and, in the HTML report, at the top of the Findings section
  — inside it rather than as its own top-level section, so it reads as "here's what to look at
  first within these findings" rather than a fifth thing to scroll past before the findings even
  start. Pure aggregation of data every format already collects — no new detection logic, and
  JSON/CSV/SARIF are unaffected (each is consumed by tooling that does its own sorting).
- HTML report: the "Checks performed" section's three rule-reference tables (Security/
  Performance/Style — every rule that *can* fire, not what actually did) are now collapsed-by-
  default accordions instead of always-expanded tables, matching the same pattern individual rule
  groups under Findings already used. With 26 security rules alone, showing all three tables
  expanded on load buried Findings and Top priorities under a wall of reference rows nobody asked
  to see first.
- Repositioned the README, gemspec, docs site, and llms.txt around this: Scryer's differentiator
  isn't "one command instead of several tools," it's ranking risk *across* security, performance,
  dependencies, and code quality — something none of RuboCop/Brakeman/bundler-audit do even
  within their own domain, let alone across all four. The honest heuristic-vs-taint-analysis
  framing versus Brakeman (and the `idor` false-positive caveat) carries over unchanged from the
  1.0.0 comparison table — this is a reframing of what Scryer adds, not a new claim about
  detection accuracy.

- False-positive hardening pass across every rule added in 1.0.0 (10 security rules) plus every
  pre-1.0.0 rule (the original 9 security checks, 4 performance rules, `frozen_string_literal`):
  each rule was tested against realistic *safe* Rails idioms (not just its original single "clean"
  fixture) run through the actual scanner, not reasoned about in the abstract. Real false
  positives found and fixed:
  - `job_raw_params` — `params.dig(:x)` and `params.permit(...)` (Rails' own narrow/allowlisting
    extraction idioms) were treated the same as forwarding the raw `params` hash; now recognized
    as narrow, alongside the existing `params[:x]` exemption.
  - `weak_crypto` — a same-line substring match on "password" false-positived on
    `passwordless_token`-style identifiers and on a defensive comment explicitly disclaiming
    password use (`# cache key, not a password hash`); both now excluded.
  - `cors_misconfiguration` — checked wildcard-origin and `credentials: true` file-wide instead of
    per `allow do...end` block, flagging a common legitimate pattern (a public wildcard-origin API
    and a separate, properly-credentialed partner API in the same initializer). Now scoped per
    block.
  - `idor` — `after_action :verify_authorized`/`:verify_policy_scoped` (Pundit's own safety-net
    callbacks) weren't recognized as guards since they're passed as callback-name arguments, not
    called directly; also added CanCanCan's `load_and_authorize_resource`/`authorize_resource`.
  - `ssrf` — a URL with a fixed, literal host and only a path segment derived from `params`
    (`"https://api.example.com/users/#{params[:id]}"`) was flagged with the same severity/message
    as a fully attacker-controlled URL; now downgraded to a warning with an accurate message
    (still flagged — a dynamic path on a fixed host isn't zero-risk — just not overstated).
  - `path_traversal` — `send_file`/`send_data`'s keyword options (`filename:`, `type:`,
    `disposition:`, which only affect response headers, never the filesystem) were checked for
    `params` the same as the actual path argument.
  - `inefficient_save_loop` — added a `db/seeds.rb`/`db/seeds/**` exemption (a one-time setup
    script, not a request-handling hot path) but the first version compared against the file path
    without accounting for the `./` prefix `Scanner` actually produces, so the exemption silently
    never matched; fixed and re-verified against a real `Scryer::Scanner` run, not a hand-built
    `Rule` instance.
  - `authentication_bypass` — an `only:`-scoped skip (a common, often-legitimate pattern for
    public actions on an authenticated controller) got the same "this is reachable without login"
    wording as an unscoped skip; message now distinguishes the two (detection unchanged — a scoped
    skip is still worth a human glance, just not implied to be a bug on its own).
  - Two disclosed-but-not-fixed gaps, documented in-code rather than silently left: `idor`'s
    already-known imprecision is joined by `graphql_missing_query_limits` (misses limits set via
    an `include`d module rather than the class body directly — real cross-file resolution, not a
    same-file AST tweak) and `active_storage_inline_disposition` (doesn't cross-reference the
    separate content-type-validation rule, since the realistic case spans two different files).
  - Everything else audited (`sql_injection`, `mass_assignment`, `command_injection`,
    `hardcoded_secret`, `unsafe_deserialization`, `xss_unsafe_html`, `csrf_protection`,
    `open_redirect`, `force_ssl_disabled`, `weak_session_cookie`, `insecure_cookie_serializer`,
    `hardcoded_basic_auth`, `security_headers_disabled`, `jwt_insecure_usage`,
    `action_cable_forgery_protection_disabled`, `hardcoded_secret_key_base`,
    `n_plus_one_query`, `missing_pagination`, `unbounded_table_scan`, `frozen_string_literal`)
    was verified clean against the same battery of realistic safe-idiom fixtures — no changes
    needed.
  - Every fix was re-verified against its rule's original true-positive case to confirm nothing
    was silenced along with the false positive.

## [1.0.0] - 2026-08-13

Seventeen new security rules, a SARIF report format, a Ruby end-of-life check, and a
credentials-exposure check — see the README's "Scryer vs RuboCop vs Brakeman vs bundler-audit"
section for how the new security coverage is positioned (heuristic pattern-matching, not taint
analysis; `idor` in particular carries real false-positive risk by nature of the problem).

- New security rules (all `category: "security"`, skippable individually via `--skip RULE_ID` /
  `c.skip_rules`, same as every other rule):
  - `force_ssl_disabled` — `config.force_ssl = false`.
  - `weak_session_cookie` — `session_store :cookie_store` with no `secure: true`.
  - `insecure_cookie_serializer` — `cookies_serializer = :marshal` (Rails defaults to the safe
    `:json`; only an explicit opt-out is flagged).
  - `authentication_bypass` — `skip_before_action` naming a common auth filter
    (`authenticate_user!`, etc.).
  - `hardcoded_basic_auth` — `http_basic_authenticate_with` with a literal `password:`.
  - `idor` — `Model.find(params[...])` in a controller with no visible authorization call
    (`authorize`/`policy_scope`/`can?`) anywhere in the class. The least precise rule in the gem —
    expect real false positives on admin-gated or genuinely-global-model controllers.
  - `ssrf` — an outbound HTTP call (`Net::HTTP`, `URI.open`/bare `open`, `HTTParty`, `Faraday`,
    `RestClient`) with a `params`-derived URL.
  - `path_traversal` — a filesystem call (`File.*`, `Dir.*`, `send_file`) with a `params`-derived
    path; recognizes `File.basename(...)` as sanitization and doesn't flag it.
  - `active_storage_missing_content_type_validation` — `has_one_attached`/`has_many_attached` with
    no matching `validates ..., content_type: [...]`.
  - `active_storage_inline_disposition` — `disposition: "inline"` on a blob/variant URL helper.
  - `security_headers_disabled` — an explicit insecure override of a Rails default security
    header/config: `X-Frame-Options`/`X-Content-Type-Options` set to `ALLOWALL`/falsy via
    `config.action_dispatch.default_headers`, or `config.content_security_policy = nil`. Absence of
    a header isn't flagged, same reasoning as `force_ssl_disabled`.
  - `cors_misconfiguration` — a wildcard `origins '*'` combined with `credentials: true` on a
    `resource` call anywhere in the same file (the standard Rack::Cors antipattern; either half
    alone is fine). Checked file-wide rather than same-block, same looseness as `idor`.
  - `jwt_insecure_usage` — `JWT.decode(token, secret, false, ...)` (signature verification
    disabled), `algorithm: 'none'`/`'alg' => 'none'`, or a literal string passed directly as the
    secret/key argument to `JWT.decode`/`JWT.encode`.
  - `action_cable_forgery_protection_disabled` —
    `config.action_cable.disable_request_forgery_protection = true`.
  - `hardcoded_secret_key_base` — `config.secret_key_base = "literal"`, a `.field=` shape
    `hardcoded_secret` misses (its target-name lookup returns the receiver's name — `config` —
    rather than the attribute being assigned; see this new rule's comment for the full
    explanation).
  - `job_raw_params` — `SomeJob.perform_async`/`perform_later`/`perform_now` called with an
    argument that references `params` — Sidekiq stores job args in Redis in plaintext (visible in
    its web UI) and both Sidekiq and ActiveJob log them by default.
  - `graphql_missing_query_limits` — a `class X < GraphQL::Schema` with no `max_depth` or
    `max_complexity` call anywhere in its body (one finding per class, not per missing directive).
- New `Scryer::DependencyAudit.credentials_exposure_check` — flags `config/master.key` existing on
  disk with no `.gitignore` line excluding it (checks both `/config/master.key` and
  `config/master.key` forms). Runs alongside the other dependency checks (same
  `--no-deps`/`nodeps` opt-out).
- New shared `Ast` helpers backing the above (and available to any future rule):
  `references_params?`, `keyword_arg`, `literal_text`, `true_literal?`/`false_literal?`. Also
  fixed `Ast.call_name` to recognize `:command_call` nodes (`config.session_store :x, y: z` —
  receiver + args, no parens), which it previously returned `nil` for.
- New `Scryer::DependencyAudit.ruby_eol_check` — flags the Ruby version pinned in Gemfile.lock's
  `RUBY VERSION` section if its series is past Ruby's own published end-of-life date. Runs
  automatically alongside the other dependency checks (same `--no-deps`/`nodeps` opt-out).
  Deliberately not a general Ruby-interpreter CVE feed — OSV.dev has no queryable ecosystem for
  that, and a maintained local CVE list would be exactly the kind of stale bundled knowledge base
  this gem avoids elsewhere; EOL dates, unlike CVEs, are announced years ahead and don't change.
- New `.sarif` report format (`scryer -o report.sarif` / `scryer:report[sarif]`) — SARIF 2.1.0,
  the format GitHub Code Scanning and similar CI dashboards ingest natively for inline PR
  annotations. Pure mapping of the same data every other format has; see the README's new
  "CI/CD integration" section for a GitHub Actions example.
- Fixed: dependency-finding display (HTML and CSV) dropped a finding's `title` entirely when it had
  no `advisory_id` (true for the new `ruby_eol` finding) instead of showing the title on its own.

## [0.3.0] - 2026-08-11

- New `scryer -r PATH`/`--require PATH` flag (repeatable): requires a Ruby file before scanning.
  This is the standalone executable's only way to run `Scryer.configure` (set `c.ai_client`,
  `c.skip_rules`, `c.dirs`, etc.) before a scan starts — unlike a Rails app, `scryer` has no
  `config/initializers/` to autoload, so AI-assisted fix suggestions and other config were
  previously unreachable outside Rails. See the README's AI-assisted fix suggestions section for
  a full step-by-step for both the Rails and standalone paths.
- Fixed: the HTML report rendered a finding's `suggested_fix` as one plain escaped string, so
  Markdown from an AI-rewritten fix (`**bold**`, ```` ```fenced code``` ````) showed up as literal
  asterisks/backticks instead of formatted text. Added a small Markdown-to-HTML renderer
  (bold, inline code, fenced code blocks, paragraphs) used for every `suggested_fix` — static
  template text or LLM rewrite, security/performance/style/dependency findings alike. Raw text is
  always escaped before any tag is added, so this doesn't open an HTML/script injection path even
  for a fully untrusted LLM response; JSON/CSV output is unaffected and still carries the original
  raw text.

## [0.2.0] - 2026-08-11

- New `style` rule category (`Scryer::RuleSet` category `"style"`, alongside `security` and
  `performance`): a deliberately narrow first check, `frozen_string_literal`, flags Ruby files
  missing the `# frozen_string_literal: true` magic comment (info severity). Findings appear
  everywhere other findings do (JSON/HTML/CSV reports, AI-assisted fix suggestions, `--skip`), and
  are counted under "Code Quality" in the summary box alongside duplicate-code groups. This
  remains the *only* style/lint check Scryer performs — see the README's Scryer-vs-RuboCop
  comparison for why the rest of that territory is intentionally left to RuboCop.
- Fixed: `bin/rails scryer:report` now fails (non-zero exit) when security or dependency findings
  are present, matching `scryer` (the standalone executable) and `scryer:audit_dependencies`. Previously
  it always exited 0 regardless of findings, so it couldn't actually gate a CI job the way the
  README described.
- Added `LICENSE.txt` (MIT) — declared via `spec.license` since 0.1.0 but not previously shipped
  as an actual file.
- `spec.homepage` now points to the live docs site (https://ramlaxmanyadav.github.io/scryer/)
  instead of the GitHub repo — the repo is still one click away via `source_code_uri` in
  `spec.metadata`.

## [0.1.0] - 2026-08-10

Initial release.

- Static security scan (`Ripper`-based, no Rails/Bundler needed to run it): SQL injection, mass
  assignment, command injection, hardcoded secrets, unsafe deserialization, XSS-prone unescaped
  HTML, CSRF gaps, weak cryptography, open redirects.
- Performance heuristics: N+1 queries, missing pagination, inefficient per-record saves, unbounded
  full-table iteration.
- Duplicate/near-duplicate code detection via token-normalized similarity.
- Dependency audit against `Gemfile.lock` — known-vulnerable gem versions (live OSV.dev query) and
  insecure git/http sources — runs by default on every scan (`--no-deps`/`nodeps` to opt out).
- Rule skipping: `c.skip_rules` / `--skip RULE_ID` to silence a specific check without editing it.
- One-off single-gem vulnerability lookup: `scryer --check-gem NAME[:VERSION]`.
- JSON, self-contained HTML, and CSV report formats.
- Optional, provider-agnostic AI-assisted fix suggestions (`Scryer::AiFixSuggester` +
  `Scryer::AiClient`) — bring any LLM via a `#call(prompt)`/`#complete(prompt)` interface.
- Opt-in runtime query watcher (`Scryer::QueryWatcher`) for N+1s and unused eager loading during
  actual request handling.
- `scryer` standalone executable and `scryer:report`/`scryer:audit_dependencies` Rails rake tasks.

[1.0.0]: https://github.com/ramlaxmanyadav/scryer/releases/tag/v1.0.0
[0.3.0]: https://github.com/ramlaxmanyadav/scryer/releases/tag/v0.3.0
[0.2.0]: https://github.com/ramlaxmanyadav/scryer/releases/tag/v0.2.0
[0.1.0]: https://github.com/ramlaxmanyadav/scryer/releases/tag/v0.1.0
