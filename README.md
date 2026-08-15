# Scryer — Ruby & Rails Application Security & Risk Auditor

Scryer scans a Ruby/Rails codebase and answers a different question than a single-purpose linter
does: not just "what's wrong," but **what's actually worth fixing first**. It looks across
security vulnerabilities, performance problems, dependency risk, and code quality in one pass,
ranks what it finds by severity, and surfaces the handful of issues that matter most at the top of
every report — with a human-reviewable suggested fix for each one.

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
[Security score](#security-score) for what it does and doesn't mean). "Top priorities" is the same
severity ranking [`ReportRenderer#top_risks`](lib/scryer/report_renderer.rb) applies across *all*
categories — security, dependencies, performance, code quality — not just within each one; in the
HTML report it's at the top of the Findings section, ahead of the 309 individual findings
underneath it. See
[Scryer vs RuboCop vs Brakeman vs bundler-audit](#scryer-vs-rubocop-vs-brakeman-vs-bundler-audit)
below for exactly how this differs from what those tools do.

### What Scryer detects

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
  [comparison table](#scryer-vs-rubocop-vs-brakeman-vs-bundler-audit) for the false-positive tradeoff.
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
  [comparison table](#scryer-vs-rubocop-vs-brakeman-vs-bundler-audit) for why not more)

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

**Runtime** (opt-in, needs a running app — see [Runtime query watcher](#runtime-query-watcher) and
[Runtime authorization watcher](#runtime-authorization-watcher))

* N+1 queries and unused eager loading, as they actually happen
* A write action that completed with no Pundit/CanCanCan authorization check actually invoked
  during that request — a live, false-positive-resistant companion to the static `idor`/
  `missing_authorization`/`missing_policy_scope` rules above

### Example findings

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

### Reports

Generate detailed JSON or self-contained HTML reports:

```bash
scryer -o report.json -o report.html
```

The HTML report leads with a [security score](#security-score) badge and a severity distribution
chart, then Overview/Summary/OWASP coverage, collapsed-by-default reference tables (every rule
that *can* fire, not a wall of always-expanded detail), and the Findings section itself — Top
priorities first, then a text filter box (rule/file/message, no page reload) above the full
severity-grouped, accordion-collapsed list. Each finding also shows its CWE ID, OWASP category, and
confidence level as small tags; clicking a count in the OWASP coverage table jumps to Findings with
that exact category pre-filled into the search box, so "how many `A01` findings are there" and
"which ones, specifically" are one click apart instead of two different views.

### Developer-friendly suggestions

Every finding includes a human-reviewable suggested fix. Scryer never automatically modifies your source code.

### Runtime analysis

Scryer can optionally monitor ActiveRecord queries at runtime to detect N+1 queries and unused eager loading.

### Designed for Ruby

Scryer uses Ruby's standard-library `Ripper` parser, allowing source analysis without requiring Rails or Bundler to run the static scan itself.

Several more things live alongside the static scan, each documented in its own section below:

- **Skipping rules** ([Skipping rules](#skipping-rules)): silence a specific rule by `rule_id`
  (config-wide via `c.skip_rules`, or one-off via `--skip`) without editing or deleting it.
- A **dependency audit** ([Dependency audit](#dependency-audit)), on by default, that checks
  `Gemfile.lock` against [OSV.dev](https://osv.dev) for known-vulnerable gem versions and insecure
  sources — the same broad goal as [bundler-audit](https://github.com/rubysec/bundler-audit), built
  independently on a different data source. Pass `--no-deps` (or the `nodeps` rake arg) for a fast,
  fully offline run instead.
- **AI-assisted fix suggestions** ([AI-assisted fix suggestions](#ai-assisted-fix-suggestions)),
  optional, provider-agnostic: rewrites each finding's `suggested_fix` against its actual code
  using an LLM you configure — any LLM, not a specific vendor.

**Nothing is auto-applied.** A security or performance fix needs a human's judgment about the
surrounding code; this gem's job is to point at the issue and explain it clearly, not to rewrite
your files. This holds whether `suggested_fix` came from a rule's static template or from the
optional AI enrichment below — either way, it's text for a human to read and act on.

## A note on how this gem was actually verified

Unlike most hand-written Rails work, this gem's core scanning engine was genuinely executed
during development — `Ripper` needs no Rails or bundler to run, so every rule here was tested
against real vulnerable-code and clean/fixed-code fixtures, not just written and hoped for. Where
a rule produced a false positive during that testing (an actual one did — `BCrypt::Password.create`
initially tripped the mass-assignment rule meant for `Model.create(params)`), it was caught and
fixed before being considered done. That's a meaningfully higher bar of confidence than most of
this account's Rails-app work, which can't be executed in the sandbox it was built in.

That said: this is a heuristic tool, not full data-flow/taint analysis (that's what a mature tool
like Brakeman spends years building). Expect some false positives and false negatives — that's
normal for this class of tool, not a bug. An already-guarded call can still get flagged since
rules don't trace surrounding conditionals — always review a finding in its surrounding context
before acting on it.

## Security score

Every scan produces a single 0-100 score plus a letter grade (A-F), shown in the console summary
and as a badge at the very top of the HTML report:

```
Security Score: 11/100 (F)
```

The formula (`ReportRenderer#security_score` in `lib/scryer/report_renderer.rb`): every security
and dependency finding costs points, weighted by both its severity *and* its confidence (a
`low`-confidence `idor` finding costs less than a `high`-confidence `sql_injection` finding at the
same severity), combined via exponential decay from 100 rather than linear subtraction — one
critical finding visibly moves the score (100 → ~86) without a handful of findings driving any
real app straight to a hard-clamped 0.

Two things worth being precise about before you treat this number as meaningful:

- **It's not normalized by app size.** A 10-file app and a 1,000-file app with the same finding
  *density* will score very differently here — this score reflects a scan's absolute finding
  exposure, not a rate. That makes it useful for tracking *one project's own trend* over time (did
  the next scan score higher or lower), not for comparing two differently-sized codebases against
  each other.
- **Performance and code-quality findings aren't part of it.** This is a *security* score — only
  security and dependency findings count. A slow app with clean security findings still scores
  well here; check the "Performance"/"Code Quality" rows in the summary box separately for that.

Alongside the score, every scan also reports a **rule-level pass rate** — "how many of Scryer's
registered checks fired zero findings":

```
Checks: 23/36 rules clean (63.9%)
```

This is the closest thing Scryer has to Brakeman's "X checks, Y warnings" framing — a coverage
signal, not a risk signal. It's deliberately a *different* number from the security score, and the
two won't always agree: a codebase can have a high clean rate (few distinct rules ever fire) and
still a low score (the few that did fire were severe and high-confidence), or the reverse (many
different rules each firing once, none of them serious). `ReportRenderer#rules_clean_rate` computes
it from `Scryer::RuleSet.all` (every registered security/performance/style rule) against which
rule_ids actually appeared in this scan's findings — dependency checks aren't counted here since
they're not backed by a `Scryer::Rule` subclass. Report both; neither alone tells the whole story.

The 10/F above is a real score from the acme-app example, not a cherry-picked good result — see
[A note on how this gem was actually verified](#a-note-on-how-this-gem-was-actually-verified) for
why every example in this README is real output.

## Accuracy benchmark

Every rule in this gem is heuristic pattern-matching — stated throughout this README, but until now
never backed by a measured number, just "expect some false positives, that's normal for this class
of tool." [`benchmark/`](benchmark/) turns that into an actual precision/recall benchmark: a
hand-labeled corpus of small Ruby/Rails snippets per rule (`benchmark/corpus.rb`), each marked
`vulnerable` (should fire) or `safe` (should NOT fire — including deliberately close "near miss"
samples that resemble the vulnerable shape, not just obviously unrelated code), run through the
real `Scryer::Rule#scan` — the same code path an actual scan uses, not a simulation.

```bash
rake benchmark          # or: ruby benchmark/run.rb
```

Current numbers, across all 36 registered rules and 180 labeled samples:

| | TP | FN | FP | TN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| **All 36 rules** | 82 | 3 | 1 | 94 | **98.8%** | **96.5%** | **97.6%** |

Two rules score below 100% — both are gaps this gem already disclosed in the rule's own top comment
before this benchmark existed, now actually measured instead of just asserted:

- **`graphql_missing_query_limits`** (50% precision, 50% recall on its 4 samples): misses a schema
  that gets its query limits through a shared custom base class or an `include`d module — both
  require cross-file resolution this per-file rule doesn't attempt.
- **`unbounded_table_scan`** (recall 66.7%): misses an unbounded scan once the query is assigned to
  a variable before `.each` instead of chained directly (`orders = Order.where(...); orders.each`).
- **`mass_assignment`** (recall 66.7%): the one gap this benchmark actually *found*, not just
  measured — see the CHANGELOG entry on the ivar-receiver fix. The corpus's other documented
  false-negative sample for this rule (a namespaced `Admin::Order.create(...)` receiver) is still
  an open, disclosed gap.

**Read `benchmark/README.md` before quoting any of these numbers** — this is a corpus we wrote
ourselves specifically to stress-test our own rules, not an independent third-party benchmark (the
way, say, the OWASP Benchmark project is for Java tools), and not real production code the way the
acme-app numbers used throughout this README are. Treat it as a lower bound on rigor (something
concrete was actually measured) and an upper bound on confidence (real-world false-positive/
false-negative rates on *your* codebase, with its own idioms and libraries, can and will differ).

## Scryer vs RuboCop vs Brakeman vs bundler-audit

Brakeman is the deeper, more mature tool for the security categories it's spent years on — real
taint/data-flow analysis, not heuristic pattern-matching (footnote [i]). RuboCop owns style/lint
conventions; Scryer stays out of that territory except for one narrow, deliberately-scoped check
(footnote [h]). Scryer isn't trying to out-analyze either of them at their own specialty. What it
does instead: look at security, performance, dependency, and code-quality findings *together* and
rank the result by severity, so "what should I fix first" has one answer instead of four separate
tool outputs (and four different severity scales) to reconcile by hand — see footnote [j]. If you
already run Brakeman for its deeper security analysis or RuboCop for style, keep doing that; Scryer
sits alongside them and adds the cross-category picture neither one (nor bundler-audit) produces.

| Capability                               | Scryer | RuboCop  | Brakeman | bundler-audit |
|-------------------------------------------|:------:|:--------:|:--------:|:-------------:|
| Style/lint conventions                     | Partial [h] | ✅  | ❌       | ❌            |
| Rails security scanning                    | ✅ [i] | ❌       | ✅       | ❌            |
| Performance heuristics                     | ✅     | Partial [a] | ❌    | ❌            |
| Duplicate/similar code detection           | ✅     | Partial [b] | ❌    | ❌            |
| Dependency vulnerability scanning          | ✅     | ❌       | ❌       | ✅            |
| Runtime query analysis (N+1 in production) | ✅     | ❌       | ❌       | ❌            |
| HTML report                                | ✅     | Partial [c] | ✅    | ❌            |
| JSON report                                | ✅     | ✅       | ✅       | Limited [d]   |
| SARIF report (GitHub Code Scanning, etc.)  | ✅     | ❌       | ✅       | ❌            |
| Human-reviewable fix suggestions           | ✅     | Partial [e] | Partial [f] | Limited [g] |
| Cross-category risk ranking ("fix this first") | ✅ [j] | ❌  | ❌      | ❌            |
| CWE / OWASP Top 10 category tags           | ✅ [k] | ❌       | ✅ [k]   | ❌            |
| Confidence level per finding                | ✅     | ❌       | ✅       | ❌            |
| Official GitHub Action                     | ✅ [l] | ❌       | ❌       | ❌            |
| Baseline / new-vs-existing-findings diffing | ✅ [m] | ❌       | Partial [m] | ❌         |
| Overall security score                     | ✅     | ❌       | ❌       | ❌            |
| Fix verified against an actual re-scan     | ✅ [n] | ❌       | ❌       | ❌            |
| Single command covering all of the above   | ✅     | ❌       | ❌       | ❌            |

- **[a]** `rubocop-performance` adds some Ruby/Rails performance cops, but nothing like N+1-query
  or missing-pagination detection.
- **[b]** A handful of cops catch exact-duplicate patterns (e.g. `Lint/DuplicateMethods`) — no
  near-duplicate/similarity detection across methods.
- **[c]** RuboCop's built-in HTML formatter is a plain findings list, not an interactive report.
- **[d]** bundler-audit's output is primarily console text; no first-class JSON formatter.
- **[e]** RuboCop's `-A` auto-corrects many style violations directly — an automatic rewrite, not
  a human-reviewable explanation, and only for auto-correctable cops.
- **[f]** Brakeman's warnings describe the issue and a confidence level, not a concrete
  before/after code fix.
- **[g]** bundler-audit names the patched version to upgrade to; no code-level remediation (it
  doesn't operate on your code at all, only `Gemfile.lock`).
- **[h]** One check only: a missing `# frozen_string_literal: true` magic comment
  (`frozen_string_literal`, info severity). Everything else in RuboCop's style/lint domain —
  naming, layout, quote style, line length, and hundreds more — is intentionally out of scope; see
  [Skipping rules](#skipping-rules) if you don't want even this one.
- **[i]** Heuristic pattern-matching, not taint/data-flow analysis — Brakeman traces whether user
  input can actually *reach* a sink; Scryer checks whether a known-dangerous call shape and a
  `params` reference appear in the same expression. That's a real precision gap on the harder
  checks especially (`idor` in particular has real false-positive risk — see
  [What Scryer detects](#what-scryer-detects)), and it's why every finding says "review this,"
  never "this is definitely a bug."
- **[j]** Each tool ranks findings within its own domain at best (e.g. Brakeman's per-warning
  confidence level). None of them combine security, performance, dependency, and code-quality
  findings into one ranked list — that's a different question than any single tool is built to
  answer. `ReportRenderer#top_risks` sorts every severity-bearing finding from a scan (across all
  four categories) by severity, shown as "Top priorities" in the console summary and at the top of
  the HTML report — see the example near the top of this README.
- **[k]** Not a Scryer-only capability — Brakeman's own warnings already include a CWE reference.
  Scryer's version is a fuller mapping (every one of its 31 security rules carries both a CWE ID
  and an OWASP Top 10 (2021) category, aggregated into an OWASP coverage scorecard in every
  report), but the underlying idea isn't new; see
  [What Scryer detects](#what-scryer-detects) for the honesty caveat on how this mapping was built
  (Scryer's own best-effort categorization, not OWASP-audited).
- **[l]** [`action.yml`](action.yml) in this repo — `uses: ramlaxmanyadav/scryer@<version>` runs
  the scan and uploads SARIF to GitHub Code Scanning in one step, instead of hand-writing the
  workflow YAML in [CI/CD integration](#cicd-integration) yourself (that manual version still
  works and is documented there too, for anyone who wants full control over the steps).
- **[m]** Brakeman has an ignore file (`brakeman -I`) that permanently silences specific warnings
  by fingerprint — genuinely similar in mechanism to [Baseline mode](#baseline-mode)'s
  fingerprinting, marked Partial rather than ✅ here because it's a permanent suppression list you
  maintain by hand, not an explicit "show me only what's new since this snapshot, and tell me
  what got fixed" diff against a saved baseline the way `scryer --baseline` reports both.
- **[n]** `scryer verify --rule RULE_ID --file PATH` re-runs one rule against one file to confirm a
  fix actually cleared it, and — when an `ai_client` is configured — the same check runs
  automatically on every AI-rewritten `suggested_fix` before the report is written (see
  [Verifying a fix](#verifying-a-fix)). RuboCop's `-A` rewrites code directly rather than verifying
  a *suggested* fix; Brakeman and bundler-audit don't rewrite or re-check at all.

Brakeman's security analysis and RuboCop's style checks are still worth running on their own —
Scryer doesn't try to replace either, and running it alongside them costs nothing (different tools,
different config files, no shared state). What Scryer adds is the view none of them produce alone:
one ranked list of what's actually most worth fixing, built from security, performance,
dependency, and code-quality findings together.

## Install

Scryer is a development-time analysis tool, not something a running production process needs —
scope it to the `:development` group so a production deploy (typically `bundle install --without
development`, or `BUNDLE_WITHOUT=development` in CI) never installs it at all:

```ruby
# Gemfile
group :development do
  gem "scryer"
end
```

```bash
bundle install
bin/rails generate scryer:install
```

This drops a commented `config/initializers/scryer.rb` into your app — see
[Generators](#generators) below for exactly what it does and what each setting controls. Scryer
is entirely local: there is nothing to point at a server and nothing to authenticate, so the
generator's only job is letting you override the defaults (project name, which directories get
scanned, the branch label).

## Running a scan

```bash
bin/rails scryer:report   # writes tmp/scryer_report.{json,html}
```

By default this writes both `tmp/scryer_report.json` and `tmp/scryer_report.html`, and includes a
dependency audit against `Gemfile.lock` (needs network — see [Dependency audit](#dependency-audit);
pass the `nodeps` arg for a fast, fully offline run instead). Format and output path are
configurable via task args — any mix of `json`, `html`, `csv`, `sarif` plus at most one path (quote
the whole thing so your shell doesn't eat the brackets/commas, e.g.
`bin/rails 'scryer:report[json,doc/security_report.json]'`). Rake splits bracket args on every
comma, so each format is its own item in the list rather than one comma-joined string
(`scryer:report[json,html]` is two args, not `"json,html"` as one). At most one non-format,
non-`nodeps` token is accepted per call; giving two raises an error rather than guessing which one
you meant.

Outside a Rails app (or in CI, or anywhere you don't want a rake task), the gem also ships a
`scryer` executable — same idea as `brakeman -o report.json`, with `-o` repeatable and format
inferred per-file from its extension:

```bash
scryer                                    # scans ., writes tmp/scryer_report.{json,html}
scryer -o report.json                     # just one file, exact path, format from extension
scryer -o report.json -o report.html      # as many outputs as you like, one -o each
scryer -p /path/to/app -o /tmp/out.html   # -p sets the root to scan (default: cwd)
scryer --no-deps                          # skip the dependency audit for a fast offline run
scryer --help                             # full option list (--project-name, --branch, --version, ...)
```

Console output is a summary box across every category — see the box in the intro above for a real
example — followed by where each report was written.

It exits `0` when the scan is clean and `1` when there's at least one security or dependency
finding, so `scryer -o report.json` can gate a CI job the same way `brakeman -o report.json` does.
A `2` exit means a usage error (bad flag, unrecognized output extension) rather than anything
about the scan itself.

Or use the scanning engine directly as a library:

```ruby
require "scryer"
result = Scryer::Scanner.new(root: "/path/to/app").call
puts result.security_findings.size
```

Open `tmp/scryer_report.html` in a browser — it's a single self-contained file (inline CSS, no
external assets, works offline) with an overview, a summary of counts by severity, the full list
of checks that ran, a breakdown of warnings by type, every finding in detail, and duplicate-code
groups — laid out similarly to a Brakeman report. `tmp/scryer_report.json` has the same data in
machine-readable form, for feeding into your own dashboard or CI gate. `.csv`
(`scryer -o report.csv` / `rails 'scryer:report[csv]'`) is a flat one-row-per-finding table
(security + performance findings, plus dependency findings unless `--no-deps`/`nodeps` was used) —
handy for dropping into a spreadsheet or importing into a ticketing tool; it skips duplicate-code
groups, which don't reduce to a single actionable row. `.sarif` (`scryer -o report.sarif` /
`rails 'scryer:report[sarif]'`) is for feeding into a CI security dashboard instead — see
[CI/CD integration](#cicd-integration).

## CI/CD integration

`scryer -o report.sarif` writes a [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/)
report — the format GitHub Code Scanning, Azure DevOps, and most CI security dashboards ingest
natively, turning findings into inline pull-request annotations and Security-tab entries instead
of a report file nobody opens. It's a pure mapping of the same data every other format has —
security, performance, and style findings (each mapped from `Scryer::Rule.rule_id`/`severity`) plus
dependency findings (mapped from `kind`, located at `Gemfile.lock`) — so nothing behaves any
differently than it does in HTML/JSON/CSV.

### Option A: the bundled `action.yml`

[`action.yml`](action.yml) in this repo wraps the whole thing — install, scan, SARIF upload, and
correctly ordering all three so the upload still happens even when findings were reported (see the
`continue-on-error` explanation below for why that ordering matters):

```yaml
# .github/workflows/scryer.yml
name: Scryer
on: [push, pull_request]

jobs:
  scryer:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # required to upload SARIF
    steps:
      - uses: actions/checkout@v4
      - uses: ramlaxmanyadav/scryer@v1.1.0
        with:
          ruby-version: "3.3"
```

All inputs are optional — `path` (default `.`), `scryer-version` (default: latest), `extra-args`
(e.g. `--skip idor --no-deps`), `fail-on-findings` (default `true`), `upload-sarif` (default
`true`). Outputs: `sarif-path`, `json-path`, `exit-code`. See [action.yml](action.yml) for the full
input/output reference.

`@v1.1.0` above needs a matching git tag pushed to GitHub before `uses:` can resolve it — replace
it with whatever version tag you actually push (or `@main` to always track the latest commit,
accepting that it can change under you).

### Option B: hand-written steps

For full control over the individual steps (a different Ruby setup, extra caching, a different
job structure):

```yaml
# .github/workflows/scryer.yml
name: Scryer
on: [push, pull_request]

jobs:
  scryer:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # required to upload SARIF
    steps:
      - uses: actions/checkout@v4
      - uses: ruby/setup-ruby@v1
        with:
          ruby-version: "3.3"
      - run: gem install scryer
      - run: scryer -o scryer.sarif
        continue-on-error: true   # let the upload step run even on a non-zero exit; see below
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: scryer.sarif
```

`continue-on-error: true` on the scan step matters: `scryer` exits non-zero when it finds anything
(see [Running a scan](#running-a-scan)), which would otherwise skip the upload step entirely on
the run where you most want to see the results. If you want the job to still fail the build overall
on findings, check `scryer`'s own exit code in a separate step, or drop `continue-on-error` and
accept that the SARIF upload only happens on clean runs. `action.yml` (Option A) handles this
ordering for you automatically.

### Rails apps: `bin/rails scryer:ci`

Inside a Rails app (rather than the standalone `scryer` executable above), `scryer:ci` is a
memorable shortcut for the same CI-sensible defaults — JSON + SARIF under `tmp/`, dependency audit
on, same `SCRYER_BASELINE` support and same fail-the-build-on-findings behavior as `scryer:report`
— without needing to remember the bracket-arg syntax:

```bash
bin/rails scryer:ci   # same as bin/rails 'scryer:report[json,sarif]'
```

## Verifying a fix

Two ways to confirm a specific finding is actually resolved, without waiting on (or paying for) a
full rescan:

**`scryer verify`** re-parses one file and re-runs one rule against it — meant to run right after
applying a fix by hand (or reviewing an AI-suggested one):

```bash
scryer verify --rule sql_injection --file app/models/user.rb
# scryer verify: sql_injection no longer fires on app/models/user.rb — fix verified.   (exit 0)
# or: scryer verify: sql_injection still fires on app/models/user.rb (1 finding(s)):   (exit 1)
#       line 12: `where` is called with a string built via interpolation, ...
```

`--path ROOT` sets the project root `--file` is resolved against (default: current directory);
`--list-rules` prints every known `rule_id`. Deliberately narrow: this only answers "does the one
thing I targeted still fire," not "did this change introduce a different finding elsewhere" — a
normal `scryer` run (or `--baseline`) already answers that.

**AI-verified remediation** does the same check automatically when an `ai_client` is configured
(see [AI-assisted fix suggestions](#ai-assisted-fix-suggestions)) — every AI-rewritten
`suggested_fix` is re-scanned against an in-memory copy of the real file before the report is
written, and each finding gets a `fix_verified: true/false/nil` field (`true`: the rule no longer
fires with this fix applied; `false`: it was checked and still fires, or the rewritten line doesn't
even parse; `nil`: not attempted at all — no `ai_client` configured, or the AI's reply didn't
include a usable code block). The HTML report shows this as a green "AI fix verified" or red "AI
fix NOT verified" line under each finding's suggested fix. **This check itself never writes
anything to a real file** — same "never auto-applied" rule `suggested_fix` always followed, up
until `scryer fix` below, which is a deliberate, explicitly-invoked exception to that rule.

## Fix mode

`scryer fix` is the third leg of scan → fix → verify: it actually writes an AI-verified fix to the
real file, instead of only reporting it as `fix_verified: true` for a human to apply by hand.

```bash
scryer fix -r ./scryer_config.rb          # writes every independently-verified fix it can
scryer fix -r ./scryer_config.rb --dry-run   # preview only — same output, nothing written
scryer fix -r ./scryer_config.rb --rule sql_injection --file app/models/order.rb
```

```
scryer fix: 4 candidate finding(s) — asking the configured AI client for a rewrite of each,
applying only the ones independently verified to clear the finding...

Fixed 2 finding(s):
  mass_assignment — app/controllers/orders_controller.rb:8
  sql_injection — app/models/order.rb:12

2 finding(s) need manual review (fix not independently verified):
  idor — app/controllers/invoices_controller.rb:14
  csrf_protection_disabled — app/controllers/api/webhooks_controller.rb:5

Re-scanning to verify every applied fix...
Verified: all 2 applied fix(es) confirmed clean on a full re-scan.
```

**The safety gate is the same FixVerifier check described above, not a new one** — a fix only ever
gets written when re-parsing the file with that one line replaced, and re-running the one rule that
flagged it, confirms the rule no longer fires. Anything the AI couldn't produce a usable `AFTER:`
block for, or whose rewrite still fires (or doesn't even parse), is left completely alone and
listed under "need manual review" — same as it would show up in a normal report. Requires an
`ai_client`; there's no non-AI fallback, since a rule's generic `suggested_fix` is prose, not
something this command can apply mechanically.

Three things worth knowing before running it:

- **This modifies real files.** Run it in a repo under version control and review the diff
  (`git diff`) before committing — same as you'd review any auto-formatter's output
  (`rubocop -A`, `prettier --write`). Nothing here is any more "trusted" than an LLM's raw
  suggestion; the verification only confirms the *targeted rule* stops firing, not that the
  rewrite is otherwise correct, idiomatic, or free of a different problem.
- **Multiple fixes in the same file are applied highest-line-number first**, so an earlier fix
  that expands one line into several doesn't shift the line numbers a later (in file order, earlier
  in processing order) fix depends on — covered by an automated test against exactly this scenario
  (`test/fix_runner_test.rb`'s `test_line_shifting_fix_applied_first_does_not_break_an_earlier_finding`).
- **The final re-scan is the real "verify" step**, not the per-fix check — it catches anything the
  narrower per-file check couldn't see, like two fixes interacting across files. This is the same
  reason `scryer verify`'s single-rule check and a full `scryer` run answer different questions.

Inside a Rails app: `rails scryer:fix` (optionally `rails 'scryer:fix[rule_id]'` to scope to one
rule, or `SCRYER_FIX_DRY_RUN=1 rails scryer:fix` to preview) — same behavior, `c.ai_client` from
`config/initializers/scryer.rb` instead of `-r`.

## What gets scanned

By default: `app/`, `lib/`, `config/`, `db/` (relative to the app root) — configurable via
`c.dirs` in the initializer. `vendor/`, `node_modules/`, `tmp/`, `log/`, `.git/`, `spec/`, `test/`
are always skipped.

## Branch reporting

By default the `git_branch` recorded in the report comes from `git rev-parse --abbrev-ref HEAD` in
the app root. Set `c.branch` in the initializer to override this — useful in CI, where checkouts
often land in a detached-HEAD state and there's no real branch name to detect:

```ruby
Scryer.configure do |c|
  c.branch = ENV["CI_COMMIT_BRANCH"]
end
```

This only changes the label shown in the report; it does not check out a different branch or
restrict which branch can be scanned.

## Skipping rules

Every rule is heuristic, so an occasional false positive on your specific codebase is expected
(see "A note on how this gem was actually verified" above) — `skip_rules` silences one by
`rule_id` without editing or deleting the rule itself, so it still runs (and could still catch a
real issue) on every other codebase that uses this gem:

```ruby
# config/initializers/scryer.rb
Scryer.configure do |c|
  c.skip_rules = ["mass_assignment"]   # rule_id, from the finding's `rule_id` field
end
```

The `scryer` executable's `--skip RULE_ID` flag (repeatable) adds to this list for a single run
without touching the initializer — useful for a one-off "does this go away without rule X" check:

```bash
scryer --skip mass_assignment --skip weak_crypto
```

## Baseline mode

`--skip` silences a rule everywhere, permanently. Baseline mode is for the more common real-world
situation: an existing app has genuine pre-existing findings you're not going to fix today, but you
still want CI to fail on anything *new* from here on:

```bash
# Once: snapshot the current state
scryer --save-baseline tmp/scryer_baseline.json

# Every run after that: only new findings show up, count toward the exit code,
# and appear in -o reports — everything already in the baseline is suppressed
scryer --baseline tmp/scryer_baseline.json -o scryer.sarif
```

```
Baseline: tmp/scryer_baseline.json — showing new findings only (2 fixed since baseline).

Security Score: 96/100 (A)

Security                 1 finding
...
```

Findings are matched by a **fingerprint** (`rule_id` + file + the offending source text), not
file:line — an unrelated edit earlier in the same file shifting every following line number
wouldn't otherwise make an existing finding look simultaneously "new" and "fixed" on every commit.
"Fixed since baseline" counts findings that were in the baseline but aren't in this scan anymore
(across every category — security, performance, style, dependencies); duplicate-code groups aren't
part of baseline mode (they don't fit the same fingerprint shape) and always show in full.

Rails/rake equivalents: `rails 'scryer:save_baseline[tmp/scryer_baseline.json]'` to save, and
`SCRYER_BASELINE=tmp/scryer_baseline.json rails scryer:report` to compare (an env var, since rake's
bracket-arg parsing is already stretched thin between format tokens, `nodeps`, and an output path).

## Runtime query watcher

Everything above is a one-shot static scan — it reads source, never boots Rails, and can't see
what actually happens at request time. `Scryer::QueryWatcher` is different: it's an opt-in
runtime instrumentation that watches a *running* app for two of the problems
[Bullet](https://github.com/flyerhzm/bullet) is best known for catching — a collection query
followed by one repeat query per row ("N+1"), and an `.includes`/`.preload`/`.eager_load`
association that gets fetched but never actually read ("unused eager loading"). It was built
independently of Bullet, on a different mechanism (SQL-shape correlation via
`ActiveSupport::Notifications`, plus a `Module#prepend` on `ActiveRecord::QueryMethods`'s eager-load
methods and `Association#reader` — not Bullet's own per-request association bookkeeping); no
Bullet source was read or copied to build it.

Enable it from an initializer (typically gated to development/test, though nothing stops you from
running it in production if you want the noise):

```ruby
# config/initializers/scryer.rb
if Rails.env.development? || Rails.env.test?
  require "scryer/query_watcher"
  Scryer::QueryWatcher.enable!
  Rails.application.config.middleware.use Scryer::QueryWatcher::Middleware
end
```

The middleware opens one tracking scope per request and logs (via `Rails.logger` by default —
override with `Scryer::QueryWatcher.enable!(logger: ...)`) anything it finds when the request
ends. Outside a request — a Sidekiq job, a rake task, a console session — wrap the code yourself:

```ruby
findings = Scryer::QueryWatcher.watch { SomeJob.new.perform }
```

`enable!(n_plus_one_threshold: 2)` controls how many repeats of the same query shape from the same
call site count as N+1 (default: the second occurrence already means one collection load produced
more than one query). Each finding is a `Scryer::QueryWatcher::Finding` with `kind`
(`n_plus_one_query_runtime` or `unused_eager_load`), `message`, `call_site`, `count`, and
`suggested_fix` — the same shape as everything else in this gem, so it's straightforward to feed
into your own logging/alerting instead of (or alongside) the built-in logger call.

This is genuinely runtime-only: with no queries running, it finds nothing, and it never appears in
the static `tmp/scryer_report.html` output. Think of it as this gem's answer to "what actually
happened during this request", where the rest of Scryer answers "what does this code look like".

## Runtime authorization watcher

The static `idor`/`missing_authorization`/`missing_policy_scope` rules can only ever say "no call
to a known authorization method is visible anywhere in this controller's source" — which is exactly
as wrong as it sounds whenever the real check happens somewhere the static AST walk can't see (a
shared base controller, a concern, a class-level macro). `Scryer::AuthorizationWatcher` answers a
narrower but far more reliable question instead: for *this actual request*, did Pundit's
`authorize`/`policy_scope` or CanCanCan's `authorize!` genuinely get called? Both libraries already
track this themselves internally (for their own `verify_authorized`/`check_authorization` helpers)
— this watcher registers one more `after_action` alongside those and checks the same flags
(`Pundit::Authorization#pundit_policy_authorized?`/`#pundit_policy_scoped?`, CanCanCan's
`@_authorized` ivar — verified by reading both gems' actual source, not guessed).

```ruby
# config/initializers/scryer.rb
require "scryer/authorization_watcher"
Scryer::AuthorizationWatcher.enable!
```

No middleware to install and no per-request scope to open (unlike `QueryWatcher` above) — a Rails
controller instance is already fresh per request, so the `after_action` above is all `enable!`
needs. It flags a `create`/`update`/`destroy` action (or any `POST`/`PUT`/`PATCH`/`DELETE` request)
that completed successfully (status < 400) with neither flag set:

```ruby
Scryer::AuthorizationWatcher.findings
# => [#<struct Scryer::AuthorizationWatcher::Finding kind="runtime_missing_authorization",
#      message="WidgetsController#update completed a PATCH request (status 200) with no
#      authorization check actually invoked during it ...", controller="WidgetsController",
#      action="update", method="PATCH", path="/widgets/1", suggested_fix="...">]
```

Two honesty points worth being precise about:

- **Pundit/CanCanCan-only, same scope as the static rules it complements.** With neither gem
  loaded, `enable!` still runs, but every request is silently skipped — an app with fully custom,
  non-object-level authorization (a single `before_action :require_admin!`) gets no findings and no
  false-positive flood, rather than being flagged for a pattern this watcher has no way to
  recognize as intentional.
- **Write actions only.** Read-scoping gaps (an unscoped `index` — see the static
  `missing_policy_scope` rule) aren't covered here: verifying "was the returned data correctly
  scoped" at runtime, rather than "was a method called," is a materially different and harder check
  this class doesn't attempt.

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

## AI-assisted fix suggestions

Every rule already ships a generic, human-reviewable `suggested_fix` — that's always there and
needs nothing configured. `Scryer::AiFixSuggester` optionally rewrites that text per finding using
an LLM, so the suggestion is written against the finding's actual offending line instead of a
generic template. This is entirely opt-in: with no client configured, `AiFixSuggester` makes zero
network calls and every finding keeps its original `suggested_fix` — nothing below is required to
use the rest of Scryer.

### Step by step

**Inside a Rails app** — `config/initializers/scryer.rb` is autoloaded at boot, so setting
`c.ai_client` there is picked up automatically the next time you scan:

```ruby
# config/initializers/scryer.rb
Scryer.configure do |c|
  c.ai_client = ->(prompt) { MyLlmClient.chat(prompt) }   # any callable — see below for real examples
end
```

```bash
bin/rails scryer:report
```

That's the whole flow — no extra flag, no second command. Look for `Scryer: rewriting suggested
fixes via the configured AI client...` in the task's own output, then open the report: every
finding's `suggested_fix` is now the LLM's rewrite instead of the generic template.

**Outside Rails (the `scryer` executable)** — there's no `config/initializers/` to autoload here,
so `Scryer.configure` needs to actually run before the scan starts. That's what `-r`/`--require` is
for: point it at a small Ruby file that calls `Scryer.configure`, and `scryer` requires it first:

```ruby
# scryer_config.rb — anywhere in your project, any filename
Scryer.configure do |c|
  c.ai_client = ->(prompt) { MyLlmClient.chat(prompt) }
end
```

```bash
scryer -r ./scryer_config.rb
```

Same output, same "rewriting suggested fixes..." line, same result — `-r` is the only difference
between the two paths, and it's required precisely because the standalone executable has nothing
else to make `Scryer.configure` code actually run before it scans.

**Provider-agnostic by design — bring any LLM.** Scryer doesn't depend on or assume any specific
vendor's API or SDK (consistent with the zero-runtime-dependency design described in the gemspec).
`c.ai_client` accepts any object, or even a bare `Proc`/lambda, that responds to `#call(prompt)`
(or `#complete(prompt)`) and returns the model's reply as a `String` — the two examples above used
a placeholder; `Scryer::AiClient` below is a ready-made adapter for a real HTTP endpoint.

### `Scryer::AiClient` — a ready-made HTTP adapter

For the common case of a JSON/HTTP chat endpoint, `Scryer::AiClient` saves writing the request
plumbing by hand. It takes the two pieces of vendor-specific shape as plain `Proc`s and handles the
HTTP call itself (stdlib `Net::HTTP`, no gem):

```ruby
# Claude (Messages API)
Scryer.configure do |c|
  c.ai_client = Scryer::AiClient.new(
    url: "https://api.anthropic.com/v1/messages",
    headers: { "x-api-key" => ENV.fetch("ANTHROPIC_API_KEY"), "anthropic-version" => "2023-06-01" },
    build_request: ->(prompt) { { model: "claude-opus-5", max_tokens: 1024, messages: [{ role: "user", content: prompt }] } },
    parse_response: ->(json) { json.dig("content", 0, "text") }
  )
end
```

```ruby
# Any OpenAI-compatible chat completions endpoint (OpenAI itself, a local
# Ollama/vLLM server, Azure OpenAI, ...) — same adapter, different shape.
Scryer.configure do |c|
  c.ai_client = Scryer::AiClient.new(
    url: "https://api.openai.com/v1/chat/completions",
    headers: { "Authorization" => "Bearer #{ENV.fetch('OPENAI_API_KEY')}" },
    build_request: ->(prompt) { { model: "gpt-4o-mini", messages: [{ role: "user", content: prompt }] } },
    parse_response: ->(json) { json.dig("choices", 0, "message", "content") }
  )
end
```

Neither example pins Scryer to that vendor — `build_request`/`parse_response` are just data telling
`AiClient` how to shape one HTTP call; point it at any endpoint that takes a JSON body and returns
a JSON body.

### What happens with it configured

`bin/rails scryer:report` and the `scryer` executable both check `Scryer.configuration.ai_client`
after scanning and, if set, call `Scryer::AiFixSuggester.enhance_result!(result)` before rendering
— one LLM call per security/performance/style finding (plus dependency findings too, if the
dependency audit ran), run across a small thread pool (same pattern as the dependency audit's
OSV.dev lookups) rather than one at a time. A client that raises, times out, or returns nothing
usable just leaves that finding's original `suggested_fix` in place — a failed enrichment never
fails the scan.

```ruby
Scryer::AiFixSuggester.enhance!(finding)          # one Finding, in place
Scryer::AiFixSuggester.enhance_result!(result)    # every finding on a Scanner::Result, in place
```

Both `bin/rails scryer:report` and the `scryer` executable also pass `root:` so each rewritten fix
gets verified against a re-scan automatically (`finding.fix_verified` — see
[Verifying a fix](#verifying-a-fix) for what that means and how to trigger it manually with
`scryer verify`); calling `enhance!`/`enhance_result!` directly as shown above skips verification
unless you pass `root:` yourself.

**This sends code snippets to whatever endpoint you configure.** `code_snippet`, `message`, and the
file path are included in the prompt — the same privacy consideration as any third-party service:
don't point this at an endpoint you don't trust with your source, and be mindful this is a second
place (besides the HTML report itself) where finding detail leaves your machine.

## Generators

Scryer ships one generator: `scryer:install`. Run `bin/rails generate scryer:install --help`
in a host app for the full description (also in
[lib/generators/scryer/USAGE](lib/generators/scryer/USAGE)); short version:

- **What it creates**: a single file, `config/initializers/scryer.rb`, templated from
  [lib/generators/scryer/templates/scryer_initializer.rb](lib/generators/scryer/templates/scryer_initializer.rb).
  Nothing else — no routes, no migrations, no controllers/views.
- **What it doesn't do**: the rake tasks (`scryer:report`) are registered by
  [Scryer::Railtie](lib/scryer/railtie.rb) as soon as the gem is in your `Gemfile`, whether or
  not you ever run this generator. The generator exists purely to give you an editable config file.
- **Settings it exposes**: `c.project_name` (report header label), `c.dirs` (which top-level
  directories get scanned), `c.branch` (override the git branch label — see
  [Branch reporting](#branch-reporting)), `c.skip_rules` (silence specific rule_ids — see
  [Skipping rules](#skipping-rules)), `c.ai_client` (see
  [AI-assisted fix suggestions](#ai-assisted-fix-suggestions)). All are optional; the
  commented-out initializer works as-is with just `bundle install` + the generator.
- **Re-running it**: standard Thor/Rails::Generators behavior — if
  `config/initializers/scryer.rb` already exists, you'll be prompted to overwrite, skip, or diff
  rather than have it silently clobbered.

## Testing Scryer results in your own test suite

Two opt-in files turn "this app's own scan stays clean" into a normal test-suite assertion, so a
regression fails the suite the same way any other regression would, instead of only showing up the
next time someone runs `scryer` by hand. Neither loads with the gem automatically (RSpec/Minitest
are never Scryer runtime dependencies — see the gemspec) — require the one matching your test
framework yourself:

```ruby
# spec/spec_helper.rb (RSpec)
require "scryer/rspec"

RSpec.describe "security" do
  it "has no critical findings" do
    expect(Scryer.scan(root: Rails.root.to_s)).to have_no_critical_findings
  end

  it "never reintroduces the mass-assignment bug fixed in PR #123" do
    expect(Scryer.scan(root: Rails.root.to_s)).to have_no_findings_for("mass_assignment")
  end
end
```

```ruby
# test/test_helper.rb (Minitest / ActiveSupport::TestCase)
require "scryer/minitest"

class SecurityTest < ActiveSupport::TestCase
  include Scryer::MinitestAssertions

  test "no critical findings" do
    assert_no_critical_scryer_findings(Scryer.scan(root: Rails.root.to_s))
  end
end
```

`Scryer.scan(root:)` runs the same static scan `scryer:report`/the `scryer` executable do (using
`c.dirs`/`c.skip_rules` from your initializer), without needing a report written to disk —
`have_no_critical_findings`/`assert_no_critical_scryer_findings` only look at *security* findings
(same scoping as the [security score](#security-score)); `have_no_findings_for`/
`assert_no_scryer_findings_for` check a specific `rule_id` across all three static categories,
for pinning a specific bug so it can't come back unnoticed. This talks to the live filesystem on
every test run (a real `Ripper`-based scan, same cost as running `scryer` itself) — for a large app
this is meaningfully slower than a typical unit test, so it's usually one dedicated test/spec file
run occasionally (a nightly job, a pre-release check) rather than part of every `rspec`/`rails test`
invocation.

## Extending it

Every rule is a small class extending `Scryer::Rule` — see `lib/scryer/rules/*.rb` (security),
`lib/scryer/performance_rules/*.rb` (performance), and `lib/scryer/style_rules/*.rb` (style) for
the pattern. A new rule file dropped into any of the three directories is picked up automatically
(rules self-register via `Rule.inherited` — no manual wiring needed, just `self.category =
"security"|"performance"|"style"`). `Scryer::Ast` has the tree-walking helpers used throughout.

Scryer's own rules have their own Minitest suite — `rake test` (from the repo root, not inside a
host app) runs a bad/clean fixture pair against every registered rule (`test/rule_fixtures_test.rb`),
plus a completeness check that fails loudly if a new rule ships with no fixture. Add an entry to
`RuleFixturesTest::FIXTURES` for any new or changed rule — and, for a genuine false positive/
negative found against real code (not just the regression pair), add it to
[`benchmark/corpus.rb`](benchmark/corpus.rb) too (see [Accuracy benchmark](#accuracy-benchmark))
with a `note:` explaining the real-world shape it represents, so it's measured going forward
instead of just fixed once and forgotten.

## Releasing

Two GitHub Actions workflows handle this repo's own CI/CD (separate from `action.yml`, which is
what *users* of Scryer drop into their own app's CI):

- [`.github/workflows/ci.yml`](.github/workflows/ci.yml) — runs `rake test` + `rake benchmark` +
  a syntax sweep + a `gem build` sanity check on every push/PR to `main`, across every Ruby version
  `required_ruby_version` claims to support (2.7 through 3.3).
- [`.github/workflows/release.yml`](.github/workflows/release.yml) — pushing a tag matching `v*`
  re-runs the test suite, then publishes to RubyGems via
  [Trusted Publishing](https://guides.rubygems.org/trusted-publishing/) (OIDC — no API key stored
  as a GitHub secret, nothing to leak or rotate).

Trusted Publishing needs a one-time setup on rubygems.org before the release workflow can actually
publish anything (this can't be done from the repo itself — it's a rubygems.org account action):
sign in, go to the scryer gem's page → **Trusted Publishers** → add one with owner
`ramlaxmanyadav`, repository `scryer`, workflow filename `release.yml`, no environment. After that,
`git tag vX.Y.Z && git push origin vX.Y.Z` is the entire release process — bump
`lib/scryer/version.rb`, update `CHANGELOG.md`, commit, tag, push the tag, and the workflow does
the rest.

## License

MIT licensed.
