# Usage & Configuration

[← Back to Scryer — Ruby on Rails Security Auditor](../README.md)

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
[Generators](./rails-integration.md#generators) below for exactly what it does and what each setting controls. Scryer
is entirely local: there is nothing to point at a server and nothing to authenticate, so the
generator's only job is letting you override the defaults (project name, which directories get
scanned, the branch label).

## Running a scan

```bash
bin/rails scryer:report   # writes tmp/scryer_report.{json,html}
```

By default this writes both `tmp/scryer_report.json` and `tmp/scryer_report.html`, and includes a
dependency audit against `Gemfile.lock` (needs network — see [Dependency audit](./rules.md#dependency-audit);
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

**Color.** The summary box, top priorities, and `scryer fix`/`scryer verify` output are colored
automatically at a real terminal — severity labels (`critical`/`warning`/`info` → red/yellow/cyan),
the security score's letter grade (A/B green, C yellow, D/F red), fixed/skipped status lines, and
so on. Off automatically whenever it would be wrong to color: piped/redirected output (e.g. `-o -`
to a file, or piped to `less` without `-R`), [`NO_COLOR`](https://no-color.org) set, or
`TERM=dumb`. `--color`/`--no-color` force it either way regardless of any of that — e.g. `scryer
--color | less -R` to keep color through a pager. Inside a Rails app: `SCRYER_COLOR=1`/
`SCRYER_NO_COLOR=1` (env vars, same precedence as the CLI flags). No new dependency — a small
hand-rolled ANSI helper (`Scryer::Colorizer`), consistent with the zero-runtime-dependency design.

See [Exit codes](#exit-codes) for what `0`/`1`/`2` mean here and for `scryer verify`/`scryer fix`.

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

## Exit codes

| Command | `0` | `1` | `2` |
|---|---|---|---|
| `scryer` (scan) | Clean — no security or dependency findings | At least one security or dependency finding | Usage error (bad flag, unrecognized output extension) |
| `scryer verify --rule ID --file PATH` | The rule no longer fires on that file | The rule still fires (findings printed) | Usage error (unknown rule_id, missing file, unparseable source) |
| `scryer fix` | Everything matched was fixed (or nothing matched) | At least one finding still needs manual review after this run | Usage error (no `ai_client` and nothing mechanically fixable, bad flag, ...) |

Every non-zero exit is deliberate and stable across versions, so any of these can gate a CI job
directly (`scryer -o report.json || exit 1`, or just let the process's own exit code fail the
step) — this is the same contract `brakeman -o report.json` and `bundle-audit check` already use,
so swapping Scryer into an existing security-gate step doesn't change how the pipeline reacts to
it.

## CI/CD integration

`scryer -o report.sarif` writes a [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/)
report — the format GitHub Code Scanning, Azure DevOps, and most CI security dashboards ingest
natively, turning findings into inline pull-request annotations and Security-tab entries instead
of a report file nobody opens. It's a pure mapping of the same data every other format has —
security, performance, and style findings (each mapped from `Scryer::Rule.rule_id`/`severity`) plus
dependency findings (mapped from `kind`, located at `Gemfile.lock`) — so nothing behaves any
differently than it does in HTML/JSON/CSV.

### Option A: the bundled `action.yml`

[`action.yml`](../action.yml) in this repo wraps the whole thing — install, scan, SARIF upload, and
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
      - uses: ramlaxmanyadav/scryer@v1.2.0
        with:
          ruby-version: "3.3"
```

All inputs are optional — `path` (default `.`), `scryer-version` (default: latest), `extra-args`
(e.g. `--skip idor --no-deps`), `fail-on-findings` (default `true`), `upload-sarif` (default
`true`). Outputs: `sarif-path`, `json-path`, `exit-code`. See [action.yml](../action.yml) for the full
input/output reference.

`@v1.2.0` above needs a matching git tag pushed to GitHub before `uses:` can resolve it — replace
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

## Duplicate-code detection

Method/query/cache-key similarity detection across models, controllers, helpers, and concerns
(see "What Scryer detects" for how it works) runs by default. Unlike the security/performance/
style checks, it isn't a `Scryer::Rule` with its own `rule_id`, so `skip_rules` can't address it —
`c.detect_duplicates` is its own on/off switch instead:

```ruby
# config/initializers/scryer.rb
Scryer.configure do |c|
  c.detect_duplicates = false   # too noisy or too slow for this codebase
end
```

For a one-off run without touching the initializer: the standalone executable's `--no-duplicates`
flag, or the rake task's `noduplicates` bracket token (alongside `nodeps`) — either only turns
detection off for that run, never back on if `c.detect_duplicates` is already `false`:

```bash
scryer --no-duplicates
```

```ruby
rails 'scryer:report[html,noduplicates]'
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

