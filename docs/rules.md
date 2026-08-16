# What Scryer Detects

[← Back to Scryer — Ruby on Rails Security Auditor](../README.md)

## What Scryer detects

**Security**

* SQL injection
* Mass assignment
* Command injection
* Hardcoded secrets (and hardcoded HTTP Basic Auth credentials)
* Unsafe deserialization
* XSS-prone HTML
* CSRF gaps
* Weak cryptography
* Open redirects
* Server-side request forgery (SSRF)
* Path traversal
* Insecure direct object references (IDOR) — the least precise check in the gem; see
  [comparison table](./architecture.md#scryer-vs-rubocop-vs-brakeman-vs-bundler-audit) for the false-positive tradeoff.
  Correctly examines namespaced controllers too (`Admin::PostsController`,
  `Api::V1::UsersController`) — an earlier version silently skipped any namespaced class here
* A `create`/`update`/`destroy` action with no authorization check anywhere in its controller
  (broader than IDOR — catches write actions that don't call `.find` at all)
* A Pundit-using controller's `index` action querying a model directly instead of through
  `policy_scope` (the common "remembered `authorize`, forgot `policy_scope`" gotcha)
* Authentication filters explicitly skipped (`skip_before_action`) — also correctly examines
  namespaced controllers, same fix as IDOR above
* Rails security configuration: disabled HTTPS enforcement, session cookies missing the secure
  flag, the Marshal cookie serializer, disabled default security headers (`X-Frame-Options`,
  `X-Content-Type-Options`, Content-Security-Policy), Action Cable request forgery protection
  disabled, a hardcoded `secret_key_base`
* Active Storage attachments without a content-type allowlist, or served with inline disposition
* CORS misconfiguration (wildcard origin combined with `credentials: true`)
* Insecure JWT usage (`JWT.decode` with signature verification disabled, `algorithm: 'none'`, or a
  hardcoded secret)
* Background jobs (`perform_async`/`perform_later`/`perform_now`) passed raw `params` — risks
  leaking request data into Sidekiq/ActiveJob logs, Redis, or the Sidekiq web UI
* GraphQL schemas with no query depth/complexity limit (`max_depth`/`max_complexity`)
* Rails config audit: `config.consider_all_requests_local = true` left on in
  `config/environments/production.rb` (shows full debug error pages — backtrace, local variables,
  request params — to anyone who triggers an exception), `config.log_level = :debug` in production
  (logs full request params and SQL bind values), `config.hosts.clear` (disables the Host-header
  allowlist that protects against DNS-rebinding/Host-header-injection). All three are Rails
  defaults in development/test where they're completely normal — only flagged where they're
  actually risky.

Every security finding also carries a **CWE ID**, an **OWASP Top 10 (2021) category**, and a
**confidence level** (`high`/`medium`/`low`) — all three appear in every report format (JSON, CSV,
HTML, SARIF) and in the OWASP Top 10 coverage scorecard (console summary + a dedicated HTML
section). Two things worth being precise about:

- **Confidence is a different axis from severity.** Severity is "how bad is this if real";
  confidence is "how often does this specific rule's pattern-match actually reflect a real issue."
  `idor` is a good example of the split: a real IDOR is serious (`warning` severity, arguably
  understating it), but the rule's own heuristic — no visible authorization call anywhere in the
  controller class — is the least precise in the gem, so it's tagged `low` confidence. Most rules
  are `medium`; the narrowest, most literal-match rules (a hardcoded string literal, an explicit
  `= false` config assignment) are `high`.
- **The CWE/OWASP mapping is Scryer's own best-effort categorization**, chosen for practitioner
  convenience (a quick answer to "does our tooling cover OWASP category X" in a compliance
  conversation) — it is not an OWASP-endorsed mapping and hasn't been independently audited. A
  handful of the 31 assignments involved a real judgment call where a rule's issue doesn't map
  cleanly onto exactly one OWASP category (e.g. `job_raw_params`, which is as much a data-exposure
  concern as a logging one). Treat it as a useful pointer, not a certification.

**Code quality**

* Near-duplicate code
* Repeated logic
* Potentially problematic code patterns
* Missing `frozen_string_literal` magic comment (the one deliberate, narrow style check — see
  [comparison table](./architecture.md#scryer-vs-rubocop-vs-brakeman-vs-bundler-audit) for why not more)

**Performance**

* N+1 queries
* Missing pagination
* Inefficient per-record saves
* Unbounded full-table iteration

**Dependencies**

* Known dependency vulnerabilities via OSV.dev
* Insecure gem sources
* Ruby version end-of-life (no more security patches published for it, for any issue)
* `config/master.key` present on disk with no matching `.gitignore` entry

**Runtime** (opt-in, needs a running app — see [Runtime query watcher](./rails-integration.md#runtime-query-watcher) and
[Runtime authorization watcher](./rails-integration.md#runtime-authorization-watcher))

* N+1 queries and unused eager loading, as they actually happen
* A write action that completed with no Pundit/CanCanCan authorization check actually invoked
  during that request — a live, false-positive-resistant companion to the static `idor`/
  `missing_authorization`/`missing_policy_scope` rules above

## Example findings

Real output — three lines of deliberately flawed Rails code, scanned with plain `scryer`:

```ruby
def create
  @invoice = Invoice.create(params[:invoice])
end
```

```
[CRITICAL] mass_assignment — app/controllers/invoices_controller.rb:3
`create` receives `params` (or a subscript of it) directly, with no `.permit(...)` call — every
attribute in the request can be set, including ones the form/API was never meant to expose (e.g.
`admin`, `role_id`).

fix: Wrap the params in a strong-parameters method, e.g. `create(order_params)` with
`def order_params; params.require(:order).permit(:status, :total); end` — only the explicitly
permitted keys get through.
```

```ruby
Invoice.where("customer_name = '#{name}'")
```

```
[CRITICAL] sql_injection — app/controllers/invoices_controller.rb:9
`where` is called with a string built via interpolation, which lets user-controlled input change
the SQL executed.

fix: Use a parameterized form instead, e.g. `where("column = ?", value)` or the hash form
`where(column: value)` — both let Active Record escape the value safely instead of interpolating
it directly into SQL.
```

```ruby
@invoices = Invoice.where(status: "open")
@invoices.each { |invoice| invoice.account.name }
```

```
[WARNING] n_plus_one_query — app/controllers/invoices_controller.rb:14
`invoice.account` is called inside a loop — if `account` is an association, this issues a separate
query per iteration instead of one batched query (a classic N+1).

fix: Eager-load the association on the base query before the loop, e.g.
`invoices = Model.includes(:account).where(...)` (or add `:account` to an existing `.includes(...)`
call), so Rails fetches it in one extra query instead of one per record.
```

Every finding follows this shape, whichever category it's in: exactly where the issue is, why it
matters, and a fix written against your actual code — not a generic paragraph you have to
translate into your own file.

## Reports

Generate detailed JSON or self-contained HTML reports:

```bash
scryer -o report.json -o report.html
```

The HTML report leads with a [security score](./architecture.md#security-score) badge and a severity distribution
chart, then Overview/Summary/OWASP coverage, collapsed-by-default reference tables (every rule
that *can* fire, not a wall of always-expanded detail), and the Findings section itself — Top
priorities first, then a text filter box (rule/file/message, no page reload) above the full
severity-grouped, accordion-collapsed list. Each finding also shows its CWE ID, OWASP category, and
confidence level as small tags; clicking a count in the OWASP coverage table jumps to Findings with
that exact category pre-filled into the search box, so "how many `A01` findings are there" and
"which ones, specifically" are one click apart instead of two different views.

#### JSON output

`report.json`'s `security_findings`/`performance_findings`/`style_findings`/`dependency_findings`
arrays are plain objects (`Scryer::Finding#to_h`) — one real entry, unedited:

```json
{
  "rule_id": "mass_assignment",
  "category": "security",
  "severity": "critical",
  "confidence": "medium",
  "cwe": "CWE-915",
  "owasp_category": "A08:2021-Software and Data Integrity Failures",
  "file": "app/controllers/orders_controller.rb",
  "line": 3,
  "code_snippet": "Order.new(params[:order])",
  "message": "`new` receives `params` (or a subscript of it) directly, with no `.permit(...)` call — every attribute in the request can be set, including ones the form/API was never meant to expose (e.g. `admin`, `role_id`).",
  "suggested_fix": "Wrap the params in a strong-parameters method, e.g. `new(order_params)` with `def order_params; params.require(:order).permit(:status, :total); end` — only the explicitly permitted keys get through.",
  "fix_verified": null
}
```

`fix_verified` is `null` unless an [`ai_client`](./fix-mode.md#ai-assisted-fix-suggestions) is configured (then
`true`/`false`/`null` — see [Verifying a fix](./fix-mode.md#verifying-a-fix) for what each means).

#### SARIF output

`report.sarif` (SARIF 2.1.0) maps the same finding into a `results[]` entry GitHub Code Scanning
and similar dashboards understand natively:

```json
{
  "ruleId": "mass_assignment",
  "level": "error",
  "rank": 75,
  "message": { "text": "`new` receives `params` (or a subscript of it) directly, with no `.permit(...)` call — every attribute in the request can be set, including ones the form/API was never meant to expose (e.g. `admin`, `role_id`)." },
  "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "app/controllers/orders_controller.rb" }, "region": { "startLine": 3 } } }],
  "properties": { "confidence": "medium", "cwe": "CWE-915", "owasp_category": "A08:2021-Software and Data Integrity Failures" }
}
```

`level` follows severity (`critical`→`error`, `warning`→`warning`, `info`→`note`); `rank` combines
severity and confidence into one prioritization number for dashboards that sort on it. See
[CI/CD integration](./usage.md#cicd-integration) for wiring this into `github/codeql-action/upload-sarif`.

## Developer-friendly suggestions

Every finding includes a human-reviewable suggested fix. Scryer never automatically modifies your source code.

## Runtime analysis

Scryer can optionally monitor ActiveRecord queries at runtime to detect N+1 queries and unused eager loading.

## Designed for Ruby

Scryer uses Ruby's standard-library `Ripper` parser, allowing source analysis without requiring Rails or Bundler to run the static scan itself.

Several more things live alongside the static scan, each documented in its own section below:

- **Skipping rules** ([Skipping rules](./usage.md#skipping-rules)): silence a specific rule by `rule_id`
  (config-wide via `c.skip_rules`, or one-off via `--skip`) without editing or deleting it.
- A **dependency audit** ([Dependency audit](#dependency-audit)), on by default, that checks
  `Gemfile.lock` against [OSV.dev](https://osv.dev) for known-vulnerable gem versions and insecure
  sources — the same broad goal as [bundler-audit](https://github.com/rubysec/bundler-audit), built
  independently on a different data source. Pass `--no-deps` (or the `nodeps` rake arg) for a fast,
  fully offline run instead.
- **AI-assisted fix suggestions** ([AI-assisted fix suggestions](./fix-mode.md#ai-assisted-fix-suggestions)),
  optional, provider-agnostic: rewrites each finding's `suggested_fix` against its actual code
  using an LLM you configure — any LLM, not a specific vendor.

**Nothing is auto-applied.** A security or performance fix needs a human's judgment about the
surrounding code; this gem's job is to point at the issue and explain it clearly, not to rewrite
your files. This holds whether `suggested_fix` came from a rule's static template or from the
optional AI enrichment below — either way, it's text for a human to read and act on.


## Dependency audit

`Scryer::DependencyAudit` checks `Gemfile.lock` for the same broad concerns
[bundler-audit](https://github.com/rubysec/bundler-audit) targets — known-vulnerable gem versions
and insecure dependency sources — built independently on a different data source and a different
lockfile parser: rather than bundler-audit's local clone of the `ruby-advisory-db` git repo, this
queries [OSV.dev](https://osv.dev) (Google's Open Source Vulnerabilities database) live, one
lookup per gem+version, over a small stdlib-only thread pool; `Gemfile.lock` is read with a small
hand-rolled parser (see `DependencyAudit.parse_lockfile`) instead of depending on the `bundler`
library, so it works the same whether or not this happens to run under Bundler. No bundler-audit
source was read or copied to build this.

```bash
bin/rails scryer:audit_dependencies   # inside a Rails app — dependency audit only, no static scan
```

This is the one part of Scryer that needs a live network connection (to reach OSV.dev), and it
runs automatically as part of every `scryer`/`scryer:report` scan — pass `--no-deps` (CLI) or the
`nodeps` arg (rake) for a fast, fully offline run instead. `scryer:audit_dependencies` above (and
`scryer --audit-deps` below) are for when you want *only* the dependency audit, the same way
`bundle-audit check` is a separate, standalone command from your test suite. Either way it exits
non-zero if anything is found, so it can gate CI.

Three checks run, and any of them can be called on its own as a library:

```ruby
Scryer::DependencyAudit.insecure_sources(Rails.root.to_s)  # offline — no network needed
Scryer::DependencyAudit.vulnerable_gems(Rails.root.to_s)   # needs network (OSV.dev)
Scryer::DependencyAudit.ruby_eol_check(Rails.root.to_s)    # offline — checked against a small embedded table
```

- **Insecure sources**: flags any `GIT`/`PATH` block in `Gemfile.lock` whose `remote:` is
  unencrypted (`git://` or plain `http://`) — the same supply-chain concern bundler-audit's
  insecure-source check targets.
- **Vulnerable gems**: for every RubyGems-sourced gem (git/path-sourced gems are skipped — their
  version string doesn't necessarily correspond to the same code as the published gem of that
  name, so checking them against RubyGems advisories could misattribute or miss vulnerabilities),
  queries OSV.dev for known vulnerabilities affecting that exact version. Each finding carries the
  advisory id, title, a severity bucketed from OSV's own severity level, a link to the advisory,
  and the fixed version(s) to upgrade to. This is also where Rails-framework CVEs surface —
  `rails`/`actionview`/`activestorage`/etc. are just gems in `Gemfile.lock` like any other.
- **Ruby EOL**: checks the Ruby version pinned in `Gemfile.lock`'s `RUBY VERSION` section against
  Ruby's own [published end-of-life dates](https://www.ruby-lang.org/en/downloads/branches/) — once
  a series is EOL, no security patches are published for it at all, for any issue, regardless of
  how up to date every gem is. Unlike the two checks above, this doesn't call OSV.dev: EOL dates
  are announced years in advance and essentially never change, so a small embedded table
  (`DependencyAudit::RUBY_EOL_DATES`) is a one-time/occasional-update cost rather than a live feed
  — deliberately not a general Ruby-interpreter CVE database, which would mean maintaining exactly
  the kind of stale bundled knowledge base this gem avoids elsewhere (OSV.dev has no queryable
  Ruby-interpreter ecosystem to query live instead).

**From the `scryer` executable** (outside a Rails app, or in CI): `scryer --audit-deps` runs the
same three checks standalone (no static scan), same output/exit-code behavior as the rake task above.
Plain `scryer` already folds them into the normal `-o` report — one HTML/JSON/CSV file covering
static findings *and* dependency findings together — so `--audit-deps` is only for when you want
dependency findings *without* the static scan. And for a single gem, without touching
`Gemfile.lock` at all:

```bash
scryer --check-gem rack            # every advisory ever filed against rack, any version
scryer --check-gem rack:2.0.8      # only advisories affecting exactly this version
```

This is the same OSV.dev client `vulnerable_gems` uses, exposed as a one-off lookup — useful for
"is this gem I'm about to add actually fine" before it's even in your `Gemfile.lock`.

