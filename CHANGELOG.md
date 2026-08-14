# Changelog

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [1.1.0] - 2026-08-14

- `Scryer::AuthorizationWatcher` (`require "scryer/authorization_watcher"`, opt-in): a runtime
  companion to the static `idor`/`missing_authorization`/`missing_policy_scope` rules. Registers
  one `after_action` and checks Pundit's `pundit_policy_authorized?`/`pundit_policy_scoped?` and
  CanCanCan's `@_authorized` (both real, verified-by-reading-the-actual-gem-source signals, not
  guessed) to catch a write action (`create`/`update`/`destroy`, or any `POST`/`PUT`/`PATCH`/
  `DELETE`) that completed successfully with neither library's authorization check actually
  invoked during that request — a live, much lower-false-positive-risk signal than the static
  rules, which can only ever see "no call is visible in this file's source," not whether it ran.
  Silently a no-op on apps using neither library (checked per-request, not just at boot). Verified
  end-to-end against real `ActionController::Base`/`ActionController::API` + real installed
  `pundit`/`cancancan` gems (not mocked) — 7 scenarios (authorized, unauthorized,
  GET-to-a-write-action-name, plain read action, both libraries, neither library present, an
  API-only base class) all behave as designed.
- Accuracy benchmark (`benchmark/`): a hand-labeled corpus of `vulnerable`/`safe` Ruby/Rails
  snippets per rule, run through the real `Rule#scan` path, reporting measured precision/recall/F1
  per rule and in aggregate (`rake benchmark` / `ruby benchmark/run.rb`) — replacing "expect some
  false positives, that's normal for this class of tool" with an actual number. Explicitly framed
  as a synthetic, self-authored corpus, not an independent benchmark — see `benchmark/README.md`'s
  honesty caveat. Directly caught a real bug while building it: `mass_assignment` never fired on
  `@record.update(params[...])` (an instance-variable receiver) — only a bare constant or implicit
  receiver was ever recognized as "likely a model" — even though that's at least as common a
  real-world shape as `Model.new(...)`. Fixed (`IVAR_RECEIVER_METHODS`, scoped to `update`/
  `update!`/`assign_attributes`/`attributes=` only, not `new`/`create`/`create!`, to avoid matching
  `Hash#update`-style receivers) and verified against the full test suite and a real external app
  with zero regressions. Now populated for all 36 registered rules, 180 hand-labeled samples total:
  **82 TP / 3 FN / 1 FP / 94 TN — 98.8% precision, 96.5% recall, 97.6% F1** (`rake benchmark`). The
  two rules scoring below 100% (`graphql_missing_query_limits`, `unbounded_table_scan`) are gaps
  already disclosed in each rule's own top comment before this benchmark existed — this just
  measured them for the first time instead of only asserting them.
- Test suite: Scryer's own rules now have automated coverage — `rake test` (Minitest, no new
  runtime dependency) runs a bad/clean fixture pair against every one of the 36 registered rules,
  plus a completeness check that fails if a new rule ships with no fixture. Previously this gem had
  zero automated tests of its own; every rule change was verified by hand against ad hoc fixtures
  and a real external Rails app each time. 37/37 passing, 0 rule bugs found while building the
  fixtures — every rule's fixture behaved exactly as its own doc comment described.
- Testing: two new opt-in files let a host app assert its own scan stays clean as part of its
  normal test suite instead of only via a separate `scryer` run — `require "scryer/rspec"`
  (`have_no_critical_findings`, `have_no_findings_for(rule_id)` matchers) and
  `require "scryer/minitest"` (`Scryer::MinitestAssertions#assert_no_critical_scryer_findings`/
  `#assert_no_scryer_findings_for`). Neither loads automatically with the gem (RSpec/Minitest stay
  out of the runtime dependency list). New `Scryer.scan(root:)` convenience method backs both,
  reusing `c.dirs`/`c.skip_rules` from the host app's own configuration.
- `scryer verify --rule RULE_ID --file PATH`: a new CLI subcommand that re-parses one file and
  re-runs one rule against it, independent of a full scan — confirms a specific fix actually
  cleared the finding it targeted (exit 0 clean / 1 still firing), meant to run right after
  applying a fix by hand or reviewing an AI-suggested one. `--list-rules` prints every known
  rule_id.
- AI-verified remediation: when an `ai_client` is configured, every AI-rewritten `suggested_fix` is
  now automatically re-checked — the rewritten line is substituted into an in-memory copy of the
  real file (nothing written to disk) and the same rule is re-run against it. Each finding gets a
  new `fix_verified` field (`true`/`false`/`nil`; JSON/HTML only — CSV/SARIF unchanged), and the
  HTML report shows a green "AI fix verified" or red "AI fix NOT verified" line under the suggested
  fix. Required extending the AI prompt to ask for a machine-parseable `AFTER:` code block as the
  last thing in the model's reply (`Scryer::FixVerifier` parses it); shares its core re-scan logic
  with `scryer verify` above.
- 3 new Rails config-audit rules, all file-scoped to avoid flagging Rails' own development/test
  defaults: `consider_all_requests_local_production` (`config.consider_all_requests_local = true`
  in `config/environments/production.rb` — shows full debug error pages in production; critical,
  CWE-209), `verbose_production_log_level` (`config.log_level = :debug` in production — logs full
  request params and SQL bind values; warning, CWE-532), `host_authorization_disabled`
  (`config.hosts.clear` — disables Rails' Host-header allowlist entirely; any file, warning,
  CWE-350). 31 security rules total now (up from 28), 36 registered rules overall.
- Generators: the generated `config/initializers/scryer.rb` now shows commented examples for
  `c.skip_rules` and `c.ai_client`, not just `project_name`/`dirs`/`branch` — both were already
  documented in USAGE but missing from the actual template. New `bin/rails scryer:ci` rake task —
  a memorable shortcut for `scryer:report[json,sarif]`'s CI-sensible defaults.
- HTML report: every count in the Summary table and the "Warnings by type" table now links to the
  matching findings, same click-to-drill-down as the OWASP coverage table and severity chart —
  the Warnings-by-type rule-id column already linked to its rule group, but the count column next
  to it didn't; Summary's category × severity cells (e.g. "Security × Critical") had no existing
  anchor to link to at all, so each finding now carries a category tag (`security`/`performance`/
  `style`, alongside the existing CWE/OWASP/confidence tags) and the search filter was extended to
  match multiple space-separated terms (all required, not a literal multi-word phrase) so a cell
  like that can link with a two-word filter (`security critical`) precisely. Renamed the
  `.owasp-link` CSS class to `.filter-link` throughout, since it's no longer OWASP-specific.
- HTML report: the severity distribution chart's counts (Critical/Warning/Info, at the very top
  next to the score badge) are now links to the matching section under Findings — same
  click-to-drill-down as the OWASP coverage table's counts. The Findings filter box now also
  applies to Top priorities (a non-matching item hides, same as a non-matching finding elsewhere
  — previously Top priorities never changed at all while filtering), and any finding matched by
  an active filter (typed or via a click-through link) gets a visible highlight, not just "still
  shown" — the point of filtering/linking is to show *which* finding is the target, not just to
  hide the rest.
- HTML report: each finding now shows its CWE ID, OWASP category, and confidence level as small
  tags (previously this data existed in JSON/CSV/SARIF but was never actually displayed per-finding
  in the HTML report, even though the OWASP coverage scorecard summarized it). The Findings search
  box matches on these tags for free, and the OWASP coverage table's counts are now links that
  jump to Findings with that exact category pre-filled into the search — the aggregate count and
  the underlying findings are one click apart instead of two disconnected views.
- New **Security Score** — `ReportRenderer#security_score` combines every security + dependency
  finding's severity and confidence into a single 0-100 number and a letter grade (A-F), via
  exponential decay from 100 (not linear subtraction, so a handful of findings doesn't
  hard-clamp every real app to 0). Shown in the console summary (`Security Score: 11/100 (F)`)
  and as a badge + severity distribution chart at the very top of the HTML report. Deliberately
  NOT normalized by app size — see the README's new "Security score" section for what that means
  and doesn't mean. Performance/code-quality findings aren't part of it (this is a *security*
  score).
- New **rules-clean-rate** — `ReportRenderer#rules_clean_rate` reports "N/M rules clean," a
  rule-level pass rate (how many of the registered checks fired zero findings) distinct from the
  finding-weighted security score — printed alongside it (`Checks: 20/33 rules clean (60.6%)`)
  and in the HTML score panel.
- HTML report: leads with the score badge + severity chart, then Overview/Summary/OWASP
  coverage, collapsed-by-default "Checks performed" reference tables, and the Findings section —
  Top priorities first, then a new text search/filter box (rule/file/message, plain JS, no page
  reload) above the severity-grouped, accordion-collapsed finding list.
- Removed the report footer's "heuristic static analysis, not full data-flow/taint analysis —
  review every finding in its surrounding context" line — the caveat itself hasn't changed
  (still true, still documented at length in the README and in individual rule comments), but
  repeating it on every single generated report read as undermining confidence in the tool
  rather than informing. The `Generated by Scryer vX (Ruby Y)` attribution stays.
- New **baseline mode** — `scryer --save-baseline PATH` snapshots every current finding
  (security/performance/style/dependency) as a set of fingerprints; `scryer --baseline PATH`
  on a later scan reports only findings new since that snapshot (plus how many were fixed),
  so an app with real pre-existing security debt can gate CI on new issues without being forced
  to fix everything on day one. Fingerprints are `rule_id`/`kind` + file/gem + offending source
  text — deliberately NOT tied to line number, so an unrelated edit earlier in the same file
  doesn't make an existing finding look simultaneously new and fixed. Rails/rake equivalent:
  `rails 'scryer:save_baseline[PATH]'` to save, `SCRYER_BASELINE=PATH rails scryer:report` to
  compare (an env var rather than another bracket-arg token, since rake's arg parsing was
  already stretched thin). See `Scryer::Baseline` (`lib/scryer/baseline.rb`) and the README's
  new "Baseline mode" section.
- Fixed a real, shared precision bug affecting `idor`, `authentication_bypass`, and
  `csrf_protection_disabled`: all three checked whether a class was a controller via a class-name
  extraction that only handled a plain `class Foo` — a namespaced class (`class
  Admin::PostsController`, `class Api::V1::UsersController`) parses its name as a different Ripper
  shape (`:const_path_ref`, not `:const_ref`), so the class name came back `nil` and the whole
  class was silently never examined by any of the three rules. Fixed with a new shared
  `Ast.class_name` helper (verified against `Ripper.sexp` for 2- and 3-level namespacing) and
  re-verified against a real production Rails app ("acme-app" elsewhere in these docs), which uses
  namespacing extensively:
  `idor` findings 2 → 4, `csrf_protection_disabled` 0 → 3, all genuinely namespaced controllers
  that were previously invisible to these checks.
- New `idor`-adjacent rules, broadening authorization coverage beyond IDOR's specific
  find-with-no-guard pattern:
  - `missing_authorization` — a controller's `create`/`update`/`destroy` action with no
    authorization evidence anywhere in the class (catches write actions that don't call `.find`
    at all, which `idor` can't see).
  - `missing_policy_scope` — a Pundit-using controller's `index` action querying a model
    directly instead of through `policy_scope` — the common "remembered `authorize`, forgot
    `policy_scope`" gotcha, since `index` has no single record for `authorize` to check.
- Every security rule (all 28) now carries a **CWE ID**, an **OWASP Top 10 (2021) category**, and
  a **confidence level** (`high`/`medium`/`low`, distinct from `severity` — see `Rule.confidence`
  in `lib/scryer/rule.rb`). All three appear on every `Finding` and flow through every report
  format (new JSON fields, new CSV columns, and in SARIF: `external/cwe/cwe-NN` + the OWASP
  category as rule-level `tags`, plus `confidence`/`cwe`/`owasp_category` as per-result
  `properties` and a combined severity+confidence `rank`). Performance/style rules get a
  `confidence` too (no CWE/OWASP — that taxonomy is security-specific). This is Scryer's own
  best-effort categorization for practitioner convenience, not an OWASP-endorsed or independently
  audited mapping — see the README's "What Scryer detects" section for the full caveat. Brakeman
  already tags CWE and reports a confidence level for its own warnings; this isn't a novel
  capability, just a fuller version of something that idea already existed elsewhere (see the
  comparison table's new footnote).
- New `ReportRenderer#owasp_coverage` — counts security findings per OWASP Top 10 category, shown
  as a console summary block ("OWASP Top 10 (2021) coverage:") and a new HTML report section, a
  direct byproduct of every security rule now carrying an `owasp_category`.
- New [`action.yml`](action.yml) — a reusable composite GitHub Action wrapping install + scan +
  SARIF upload, correctly ordered so the upload still happens on runs where findings were found
  (previously only documented as a manual YAML snippet in the README's CI/CD section, which still
  works and is kept as the "full control" alternative).
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
  groups under Findings already used. With 28 security rules alone, showing all three tables
  expanded on load buried Findings and Top priorities under a wall of reference rows nobody asked
  to see first.
- HTML report: "Duplicate code groups" moved to after "Dependency audit"/"Files that couldn't be
  parsed", as the last section before the footer.
- Fixed: the "Dependency audit" section's "Expand all"/"Collapse all" controls did nothing —
  dependency findings rendered as plain, always-expanded `.finding` divs, never actually wrapped
  in the `.accordion` markup those buttons operate on. Each of the 24 dependency findings in a
  typical scan is now its own collapsed-by-default accordion, same pattern as Findings/Checks
  performed.
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
