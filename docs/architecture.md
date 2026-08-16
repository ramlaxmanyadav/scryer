# Architecture, Performance & Security Model

[← Back to Scryer — Ruby on Rails Security Auditor](../README.md)

## Architecture

Ruby's stdlib `Ripper` parses each file into an S-expression tree (see
[lib/scryer/ast.rb](../lib/scryer/ast.rb) for the small set of tree-walking helpers every rule uses).
Each check is a self-registering `Scryer::Rule` subclass
([lib/scryer/rule.rb](../lib/scryer/rule.rb)/[lib/scryer/rule_set.rb](../lib/scryer/rule_set.rb)) that
walks that tree looking for one specific shape — a call to a known-dangerous method, a
Rails-config assignment, a missing guard — and emits a `Scryer::Finding` when it matches.
`Scryer::Scanner` finds every Ruby file under the configured directories, parses each once, and
runs every registered rule against the resulting tree; `Scryer::ReportRenderer` merges the results
(plus a separate `Scryer::DependencyAudit` pass over `Gemfile.lock`) into JSON/HTML/CSV/SARIF and
computes the cross-category "Top priorities" ranking and security score. This is heuristic
pattern-matching on syntax, not [taint/data-flow
analysis](https://ramlaxmanyadav.github.io/scryer/taint-analysis-vs-heuristic-pattern-matching.html)
— no attempt is made to trace whether a specific value actually flows from an untrusted source to
a dangerous sink, which is exactly what makes it possible to run with zero runtime dependencies and
no Rails/database boot.

## Performance

Parsing is the only real cost, and it's linear in file count/size — there's no Rails boot, no
database connection, and (with `--no-deps`) no network call at all. A real, unscoped scan of a
236-file production Rails app (the same one behind the [Security score](#security-score) example
above) completes in about 2.5 seconds end to end on a laptop, `--no-deps` set. The one deliberately
slower path is the [dependency audit](./rules.md#dependency-audit) (on by default): it queries
[OSV.dev](https://osv.dev) once per unique gem in `Gemfile.lock`, so total time scales with distinct
dependency count and network latency, not codebase size — skip it with `--no-deps` (or `nodeps`)
for a fast, fully offline run when that matters more than dependency coverage on a given run (e.g.
a pre-commit hook, versus a full CI job).

## Security model

- **Static analysis only, by default.** The core scan reads source files and never executes your
  code. The [runtime query watcher](./rails-integration.md#runtime-query-watcher) and [runtime authorization
  watcher](./rails-integration.md#runtime-authorization-watcher) are the only things that hook into a running
  process, and both are opt-in (you register them explicitly in an initializer) — a plain `scryer`
  scan does neither.
- **No network calls except two, both skippable/opt-in.** The [dependency audit](./rules.md#dependency-audit)
  queries OSV.dev (skip with `--no-deps`); [AI-assisted fix
  suggestions](./fix-mode.md#ai-assisted-fix-suggestions) call whatever LLM endpoint you explicitly configure via
  `c.ai_client` (nothing is called with no client configured, and no code snippet leaves your
  machine unless you set one up).
- **Nothing is auto-applied without independent re-verification.** Every finding's `suggested_fix`
  is just text until you act on it — except `scryer fix` ([Fix mode](./fix-mode.md#fix-mode)), the one command
  that writes to disk, and even there only after re-parsing the file with that exact rewrite
  applied and re-running the rule against it to confirm it actually clears the finding it targeted.
- **Zero runtime dependencies** beyond Ruby's own stdlib (`ripper`, `json`, `digest`,
  `securerandom`, `set`, `net/http`, `uri`, `date`) — no transitive gem supply-chain surface to
  audit beyond Ruby itself.
- **Safe to run against untrusted source.** Because it's a syntax-level static parse (never
  `eval`, never `require`s the scanned code, never boots the target app), running Scryer against a
  codebase you don't fully trust doesn't execute anything in it.

## False-positive handling

Every finding carries a `confidence` (`high`/`medium`/`low`, distinct from severity) — Scryer's own
best-effort assessment of how likely that specific match is a real issue, not a false positive. The
`idor` rule is explicitly the least precise check in the gem (see the [comparison
table](#scryer-vs-rubocop-vs-brakeman-vs-bundler-audit) footnotes) — real false-positive risk on
admin-gated or genuinely-global-model controllers; several other rules' false-positive risks and
mitigations are documented alongside them in [What Scryer
detects](./rules.md#what-scryer-detects). When a specific rule doesn't fit your codebase:

- **Silence it entirely**: `--skip RULE_ID` (repeatable) for a one-off run, or `c.skip_rules` in
  the initializer for every run — see [Skipping rules](./usage.md#skipping-rules).
- **Suppress only pre-existing findings, not new ones**: [Baseline mode](./usage.md#baseline-mode) snapshots
  the current findings and only reports/gates on what's new since then — the practical way to adopt
  Scryer on a codebase with real pre-existing security debt without either fixing everything on day
  one or turning the gate off entirely.
- **Confirm a specific fix actually worked**: `scryer verify` ([Verifying a
  fix](./fix-mode.md#verifying-a-fix)) re-runs one rule against one file in isolation, independent of a full
  scan.

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
of tool." [`benchmark/`](../benchmark/) turns that into an actual precision/recall benchmark: a
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
  [Skipping rules](./usage.md#skipping-rules) if you don't want even this one.
- **[i]** Heuristic pattern-matching, not taint/data-flow analysis — Brakeman traces whether user
  input can actually *reach* a sink; Scryer checks whether a known-dangerous call shape and a
  `params` reference appear in the same expression. That's a real precision gap on the harder
  checks especially (`idor` in particular has real false-positive risk — see
  [What Scryer detects](./rules.md#what-scryer-detects)), and it's why every finding says "review this,"
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
  [What Scryer detects](./rules.md#what-scryer-detects) for the honesty caveat on how this mapping was built
  (Scryer's own best-effort categorization, not OWASP-audited).
- **[l]** [`action.yml`](../action.yml) in this repo — `uses: ramlaxmanyadav/scryer@<version>` runs
  the scan and uploads SARIF to GitHub Code Scanning in one step, instead of hand-writing the
  workflow YAML in [CI/CD integration](./usage.md#cicd-integration) yourself (that manual version still
  works and is documented there too, for anyone who wants full control over the steps).
- **[m]** Brakeman has an ignore file (`brakeman -I`) that permanently silences specific warnings
  by fingerprint — genuinely similar in mechanism to [Baseline mode](./usage.md#baseline-mode)'s
  fingerprinting, marked Partial rather than ✅ here because it's a permanent suppression list you
  maintain by hand, not an explicit "show me only what's new since this snapshot, and tell me
  what got fixed" diff against a saved baseline the way `scryer --baseline` reports both.
- **[n]** `scryer verify --rule RULE_ID --file PATH` re-runs one rule against one file to confirm a
  fix actually cleared it, and — when an `ai_client` is configured — the same check runs
  automatically on every AI-rewritten `suggested_fix` before the report is written (see
  [Verifying a fix](./fix-mode.md#verifying-a-fix)). RuboCop's `-A` rewrites code directly rather than verifying
  a *suggested* fix; Brakeman and bundler-audit don't rewrite or re-check at all.

Brakeman's security analysis and RuboCop's style checks are still worth running on their own —
Scryer doesn't try to replace either, and running it alongside them costs nothing (different tools,
different config files, no shared state). What Scryer adds is the view none of them produce alone:
one ranked list of what's actually most worth fixing, built from security, performance,
dependency, and code-quality findings together.

