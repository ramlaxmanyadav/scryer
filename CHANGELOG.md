# Changelog

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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

[0.2.0]: https://github.com/ramlaxmanyadav/scryer/releases/tag/v0.2.0
[0.1.0]: https://github.com/ramlaxmanyadav/scryer/releases/tag/v0.1.0
