# Fix Mode & AI-Assisted Fixes

[← Back to Scryer — Ruby on Rails Security Auditor](../README.md)

## Verifying a fix

Two ways to confirm a specific finding is actually resolved, without waiting on (or paying for) a
full rescan:

**`scryer verify`** re-checks whether specific findings still fire, without waiting on (or writing)
a full report. `--rule`/`--file` narrow the scope; omit either or both to broaden it:

```bash
scryer verify --rule sql_injection --file app/models/user.rb   # one rule, one file (narrowest)
# scryer verify: sql_injection no longer fires on app/models/user.rb — fix verified.   (exit 0)
# or: scryer verify: sql_injection still fires on app/models/user.rb (1 finding(s)):   (exit 1)
#       line 12: `where` is called with a string built via interpolation, ...

scryer verify --file app/models/user.rb    # every rule, just this one file
scryer verify --rule sql_injection         # this one rule, across the whole project
scryer verify                              # every rule, across the whole project
```

`--path ROOT` sets the project root `--file` is resolved against, or that gets checked entirely
when `--file` is omitted (default: current directory); `--list-rules` prints every known `rule_id`.
The `--rule ID --file PATH` case is deliberately the narrowest of the four: it only answers "does
the one thing I targeted still fire," not "did this change introduce a different finding
elsewhere" — that's what the broader `scryer verify` (no flags) case, a normal `scryer` run, or
`--baseline` already answer. Bare `scryer verify` covers security/performance/style findings, the
same as `--baseline` does — duplicate-code groups aren't included (they don't fit the same
single-finding shape, same reason `--baseline` excludes them too).

The three broader cases (anything other than `--rule ID --file PATH`) can turn up many findings at
once, so those print grouped by severity (critical first) with a short, length-truncated summary
per finding rather than the full message — a quick "what's still failing" glance, not a wall of
text:

```
scryer verify: still has findings under . (36 finding(s)):

  [critical] sql_injection — app/controllers/orders_controller.rb:14
      `where` is called with a string built via interpolation, which lets user-controlled input change…
  [warning] missing_authorization — app/controllers/api_keys_controller.rb:46
      `ApiKeysController#update` writes data (a standard Rails write action), and `ApiKeysController` has…
```

Full untruncated detail (every finding, unabridged) is what a real `scryer -o report.json`/
`report.html` is for — this command is meant to answer "is anything still failing," not replace a
proper report.

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

`scryer fix` is the third leg of scan → fix → verify: it actually writes a verified fix to the
real file, instead of only reporting it as `fix_verified: true` for a human to apply by hand.

**No AI required for a handful of rules.** `Scryer::MechanicalFixer` covers the small set of rules
where there's exactly one correct rewrite — no judgment call, so nothing an LLM would do
differently: `frozen_string_literal` (adds the magic comment), `sql_injection` (replaces `#{expr}`
inside the SQL string with a `?` bind parameter — only when the string is the call's sole
argument; anything more ambiguous, like an existing second argument, is left alone rather than
guessed at), and simple config flips (`force_ssl_disabled`, `insecure_cookie_serializer`,
`weak_session_cookie`, `security_headers_disabled`). These run with **no `ai_client` configured at
all**. Everything else (`mass_assignment`, `idor`, `missing_authorization`, `csrf`, ...) still needs
an `ai_client` or a manual fix — the correct rewrite depends on things Scryer can't know statically
(which params to permit, which policy to call).

**When an `ai_client` *is* configured, it's tried first for every rule** — including the six above
— so what gets written is a context-aware "real developer" fix rather than only the one
mechanically-derivable rewrite, whenever AI is actually available to provide one. The mechanical
fixer is the fallback: it only runs when AI isn't configured at all, declined to produce anything
usable, raised an error, or its rewrite didn't independently verify. Same verify-then-write pipeline
either way, so neither path is ever trusted more than the other — a fix only gets written once
`FixVerifier` confirms the targeted rule actually stops firing, regardless of which one produced it.

**Troubleshooting: "I configured an `ai_client` but everything still says 'needs manual
review'."** `Scryer.configuration.ai_client` is only set once whatever file calls
`Scryer.configure` actually *runs* — for the standalone `scryer` executable that means either
passing `-r path/to/your_config.rb`, or having a `config/initializers/scryer.rb` under `--path`
(auto-required with no `-r` at all — see below), on **every invocation**, including `scryer fix`.
With neither, `ai_client` stays `nil` for that run, and it fails exactly the same way "no client
configured at all" does: silently, with the rule's own generic `suggested_fix` text and no error.
If a config file is in play (explicit `-r` or auto-discovered) and it's still not working, check
the live progress output for a line reading `Skipped (AI client error): ...` followed by the
actual exception (a bad API key, a network timeout, a malformed response) — see
[`Scryer::AiFixSuggester`](#ai-assisted-fix-suggestions) below for how that's surfaced instead of
swallowed.

**No `-r` needed if `config/initializers/scryer.rb` already exists.** The standalone executable
auto-requires `config/initializers/scryer.rb` under `--path` whenever `-r`/`--require` is omitted
entirely — the same file a Rails app booted against this project would already autoload, so
running `scryer`/`scryer fix` against a Rails app that already has one just works with no `-r`
at all. Prints a one-line notice (`Scryer: no -r/--require given — found and requiring ...`) so
this is never a silent switch. Passing `-r` explicitly always wins and skips this entirely.

```bash
scryer fix                                # no ai_client needed for the mechanically-fixable rules
scryer fix -r ./scryer_config.rb          # writes every independently-verified fix it can, AI included
scryer fix -r ./scryer_config.rb --dry-run   # preview only — same output, nothing written
scryer fix -r ./scryer_config.rb --rule sql_injection --file app/models/order.rb
```

```
scryer fix: 4 candidate finding(s) — asking the configured AI client for a rewrite of each,
applying only the ones independently verified to clear the finding...
Fixed: mass_assignment — app/controllers/orders_controller.rb:8
  Switches to strong parameters so only explicitly permitted attributes reach `Order.new`.
Fixed: sql_injection — app/models/order.rb:12
  Replaces the interpolated string with a parameterized `where` call, so user input can never
  become part of the SQL text.
Skipped (needs manual review): idor — app/controllers/invoices_controller.rb:14
Skipped (needs manual review): csrf_protection_disabled — app/controllers/api/webhooks_controller.rb:5

Fixed 2 finding(s):
  mass_assignment — app/controllers/orders_controller.rb:8
  sql_injection — app/models/order.rb:12

2 finding(s) need manual review (fix not independently verified):
  idor — app/controllers/invoices_controller.rb:14
  csrf_protection_disabled — app/controllers/api/webhooks_controller.rb:5

Re-scanning to verify every applied fix...
Verified: all 2 applied fix(es) confirmed clean on a full re-scan.
```

Each finding prints as soon as it's resolved — not just in the final summary — with a short 1-2
sentence explanation pulled from the AI's own reply (it's asked to lead with plain-English
reasoning before any code; see the `--rule`/`--file` prompt in `AiFixSuggester`), so you can follow
along as it works instead of waiting on a wall of silence.

**The safety gate is the same FixVerifier check described above, not a new one** — a fix only ever
gets written when re-parsing the file with that one line replaced, and re-running the one rule that
flagged it, confirms the rule no longer fires. Anything that couldn't produce a usable `AFTER:`
block (mechanical or AI), or whose rewrite still fires (or doesn't even parse), is left completely
alone and listed under "not applied" — same as it would show up in a normal report. Needs *either*
an `ai_client` configured *or* at least one matched finding covered by `Scryer::MechanicalFixer`
(see above) — refuses to run only when neither is true, since there'd be nothing it could possibly
fix.

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

**Interactive per-finding review.** Run `scryer fix` at an actual terminal (not CI, not piped
stdin) without `--yes`, and every independently-verified fix is shown — rule, message, a short
explanation, and the actual `AFTER:` rewrite — and confirmed one at a time before it's written,
instead of silently applying everything that verified clean:

```
sql_injection — app/models/order.rb:12
  `where` is called with a string built via interpolation, which lets user-controlled input change the SQL executed.
  Fix: Replaces the string interpolation inside the SQL string with a `?` bind parameter, so the value is always sent as a query parameter rather than parsed as SQL text.
  AFTER:
    Order.where("status = ?", params[:status])
Apply this fix?
  1) Yes
  2) Skip
  3) Yes to all remaining
  4) Cancel (stop reviewing — nothing further will be attempted)
Choice:
```

Numeric choices only — no y/n/a/s letters, and a blank or unrecognized answer just re-prompts
rather than guessing. `1`/`2` decide just the one shown; `3` ("yes to all remaining") latches
acceptance for every later finding this run, so accepting the rest doesn't mean answering one at a
time — that's also the fastest way to fix everything from an interactive session: pick `3` on the
very first finding. `4` ("cancel") stops immediately: every remaining candidate is marked skipped
without even asking the AI client or the mechanical fixer for a rewrite, since cancelling means
stop working, not just stop writing. A non-interactive run (CI, piped stdin) or `--dry-run` never
prompts — everything verified gets applied automatically, same as before this existed. For a
single non-interactive command that fixes everything in one shot (no terminal, no prompts, e.g. in
a script or CI), pass `--yes` instead:

```bash
scryer fix -r ./scryer_config.rb --yes
```

**Picking specific findings up front**, when `--rule`/`--file` still leave more than one candidate
and you'd rather choose by number than review each one interactively:

```bash
scryer fix --rule sql_injection --list          # numbered list, no AI calls, nothing written
scryer fix --rule sql_injection --number 2       # fix only candidate #2 from that list
scryer fix --rule sql_injection --number 1,3     # or a comma-separated set
```

Numbering is stable across runs as long as `--rule`/`--file` stay the same (candidates are sorted
by file, then line, before being numbered) — list once, then fix by number in a second, scriptable
call; `--number` skips the per-finding review entirely for whatever it selects.

**`frozen_string_literal` is opt-in.** An unscoped `scryer fix` (no `--rule`) excludes it by
default — it's a cosmetic, `info`-severity finding that would otherwise touch nearly every file in
a project. At a real terminal it asks once, up front, whether to include it (a separate, coarser
yes/no than the per-finding review above, meant to skip hundreds of individual prompts for a
low-value category in one keystroke); non-interactively it's excluded with a one-line notice.
Passing `--rule frozen_string_literal` explicitly always includes it — that's already informed
consent.

Inside a Rails app: `rails scryer:fix` (optionally `rails 'scryer:fix[rule_id]'` to scope to one
rule, `SCRYER_FIX_DRY_RUN=1 rails scryer:fix` to preview, `SCRYER_FIX_LIST=1 rails scryer:fix` to
list numbered candidates, `SCRYER_FIX_NUMBERS=2,3 rails scryer:fix` to fix only those, or
`SCRYER_FIX_YES=1 rails scryer:fix` for the non-interactive apply-everything behavior) — same
behavior, `c.ai_client` from `config/initializers/scryer.rb` instead of `-r`.

**Dependency findings (`scryer --audit-deps`'s output) are not part of any of the above** — a
`vulnerable_dependency`/`insecure_source`/`ruby_eol`/`credentials_exposure` finding has no
`.line`/`.file`/`.rule_id` to rewrite, so none of `FixRunner`/`MechanicalFixer`/`FixVerifier` apply
to it. `scryer fix --deps` is a separate, smaller pipeline (`Scryer::DependencyFixer`) that only
handles the one kind of dependency finding with an unambiguous fix — a vulnerable gem with a
published patched version:

```
scryer fix --deps --path .              # bundle update GEM --conservative per vulnerable gem, then re-check OSV.dev
scryer fix --deps --dry-run --path .    # show which gems would be updated, without running anything
```

No `ai_client` is involved — this runs a real `bundle update GEM --conservative` per distinct
vulnerable gem (never one command per advisory; a gem with two open advisories still only gets
updated once), then re-queries OSV.dev for that one gem to confirm the bump actually cleared every
advisory it had before reporting it as fixed. A gem with no published patched version yet, an
insecure `git://`/`http://` source, a past-EOL Ruby version, or an exposed `config/master.key` are
always left for manual review — none of those are a gem-version bump. This is a real, working-tree
mutation (it rewrites `Gemfile.lock`), same caution as running `bundle update` yourself directly.

Inside a Rails app: `SCRYER_FIX_DEPS=1 rails scryer:fix` (add `SCRYER_FIX_DRY_RUN=1` to preview
first).


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

