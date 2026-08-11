# Scryer — Ruby & Rails Code Security Auditor

Scryer is a Ruby static code analysis and security auditing tool. It analyzes Ruby and Rails
projects, audits `Gemfile.lock` dependencies for known vulnerabilities, identifies potential
security, performance, and code-quality issues, and gives you an actionable, human-reviewable
suggestion for fixing each one.

Most Rails teams already run several separate tools to cover code quality and security: RuboCop
for style, Brakeman for security, bundler-audit for dependency CVEs, Reek for code smells, plus
whatever custom scripts glue their outputs together in CI — different gems, different config
files, different report formats, different CI steps to maintain.

**Scryer's job is to be the one audit command that covers all of it** — security vulnerabilities,
performance problems, duplicate/smelly code, and dependency vulnerabilities — in a single scan
with a single report:

```bash
gem install scryer
scryer
```

```
Scryer Audit — 236 files scanned
────────────────────────────────

Security                8 findings
Performance            10 findings
Code Quality          248 findings
Dependencies           24 findings
────────────────────────────────
Total                 290 findings

JSON report: tmp/scryer_report.json
HTML report: tmp/scryer_report.html
```

That's real output from a scan of a live 236-file Rails app — not a mockup. See
[Scryer vs RuboCop vs Brakeman vs bundler-audit](#scryer-vs-rubocop-vs-brakeman-vs-bundler-audit)
below for exactly how it stacks up against the tools it's meant to consolidate.

### What Scryer detects

**Security**

* SQL injection
* Mass assignment
* Command injection
* Hardcoded secrets
* Unsafe deserialization
* XSS-prone HTML
* CSRF gaps
* Weak cryptography
* Open redirects

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

## Scryer vs RuboCop vs Brakeman vs bundler-audit

Scryer isn't trying to out-lint RuboCop or out-analyze Brakeman — where an existing tool
specializes, it's still worth running on its own; style/lint conventions are almost entirely
RuboCop's job, and Scryer stays out of that territory except for one narrow, deliberately-scoped
check (see footnote below). What Scryer actually replaces is *stitching several of these together
yourself*: it covers categories none of the others do alone (performance heuristics,
duplicate-code detection, runtime query analysis), and folds the categories they *do* cover into
one command and one report instead of several separate tools, configs, and CI steps.

| Capability                               | Scryer | RuboCop  | Brakeman | bundler-audit |
|-------------------------------------------|:------:|:--------:|:--------:|:-------------:|
| Style/lint conventions                     | Partial [h] | ✅  | ❌       | ❌            |
| Rails security scanning                    | ✅     | ❌       | ✅       | ❌            |
| Performance heuristics                     | ✅     | Partial [a] | ❌    | ❌            |
| Duplicate/similar code detection           | ✅     | Partial [b] | ❌    | ❌            |
| Dependency vulnerability scanning          | ✅     | ❌       | ❌       | ✅            |
| Runtime query analysis (N+1 in production) | ✅     | ❌       | ❌       | ❌            |
| HTML report                                | ✅     | Partial [c] | ✅    | ❌            |
| JSON report                                | ✅     | ✅       | ✅       | Limited [d]   |
| Human-reviewable fix suggestions           | ✅     | Partial [e] | Partial [f] | Limited [g] |
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

If you already run RuboCop for style, keep it — Scryer isn't a replacement for it. If you're
currently running Brakeman + bundler-audit + a duplicate-code linter as three separate steps,
Scryer is the "run one thing instead" option.

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
configurable via task args — any mix of `json`, `html`, `csv` plus at most one path (quote the
whole thing so your shell doesn't eat the brackets/commas, e.g.
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
machine-readable form, for feeding into your own dashboard or CI gate. A third format, `.csv`
(`scryer -o report.csv` / `rails 'scryer:report[csv]'`), is a flat one-row-per-finding table
(security + performance findings, plus dependency findings unless `--no-deps`/`nodeps` was used) —
handy for dropping into a spreadsheet or importing into a ticketing tool. It skips duplicate-code
groups, which don't reduce to a single actionable row.

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

Two checks run, and either can be called on its own as a library:

```ruby
Scryer::DependencyAudit.insecure_sources(Rails.root.to_s)  # offline — no network needed
Scryer::DependencyAudit.vulnerable_gems(Rails.root.to_s)   # needs network (OSV.dev)
```

- **Insecure sources**: flags any `GIT`/`PATH` block in `Gemfile.lock` whose `remote:` is
  unencrypted (`git://` or plain `http://`) — the same supply-chain concern bundler-audit's
  insecure-source check targets.
- **Vulnerable gems**: for every RubyGems-sourced gem (git/path-sourced gems are skipped — their
  version string doesn't necessarily correspond to the same code as the published gem of that
  name, so checking them against RubyGems advisories could misattribute or miss vulnerabilities),
  queries OSV.dev for known vulnerabilities affecting that exact version. Each finding carries the
  advisory id, title, a severity bucketed from OSV's own severity level, a link to the advisory,
  and the fixed version(s) to upgrade to.

**From the `scryer` executable** (outside a Rails app, or in CI): `scryer --audit-deps` runs the
same two checks standalone (no static scan), same output/exit-code behavior as the rake task above.
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
generic template.

**Provider-agnostic by design — bring any LLM.** Scryer doesn't depend on or assume any specific
vendor's API or SDK (consistent with the zero-runtime-dependency design described in the gemspec).
Configure `c.ai_client` to any object, or even a bare `Proc`/lambda, that responds to `#call(prompt)`
(or `#complete(prompt)`) and returns the model's reply as a `String`:

```ruby
# config/initializers/scryer.rb
Scryer.configure do |c|
  # Simplest form: any callable. Wire up whatever SDK/gem you already use —
  # Scryer never requires one itself.
  c.ai_client = ->(prompt) { MyLlmClient.chat(prompt) }
end
```

This is entirely opt-in: `c.ai_client` is `nil` by default, and with no client configured
`AiFixSuggester` makes zero network calls and every finding keeps its original `suggested_fix`.

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
— one LLM call per security/performance finding, run across a small thread pool (same pattern as
the dependency audit's OSV.dev lookups) rather than one at a time. A client that raises, times out,
or returns nothing usable just leaves that finding's original `suggested_fix` in place — a failed
enrichment never fails the scan.

```ruby
Scryer::AiFixSuggester.enhance!(finding)          # one Finding, in place
Scryer::AiFixSuggester.enhance_result!(result)    # every finding on a Scanner::Result, in place
```

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
  [Branch reporting](#branch-reporting)). All are optional; the commented-out initializer works
  as-is with just `bundle install` + the generator.
- **Re-running it**: standard Thor/Rails::Generators behavior — if
  `config/initializers/scryer.rb` already exists, you'll be prompted to overwrite, skip, or diff
  rather than have it silently clobbered.

## Extending it

Every rule is a small class extending `Scryer::Rule` — see `lib/scryer/rules/*.rb` (security),
`lib/scryer/performance_rules/*.rb` (performance), and `lib/scryer/style_rules/*.rb` (style) for
the pattern. A new rule file dropped into any of the three directories is picked up automatically
(rules self-register via `Rule.inherited` — no manual wiring needed, just `self.category =
"security"|"performance"|"style"`). `Scryer::Ast` has the tree-walking helpers used throughout.

## License

MIT licensed.
