# Configuration for the scryer gem (static code analysis: security,
# duplicate code, performance heuristics). Run `bin/rails scryer:report`
# to scan this app and generate tmp/scryer_report.{json,html} locally.

Scryer.configure do |c|
  c.project_name = "my-rails-app"

  # Which top-level directories to scan (relative to Rails.root). Defaults
  # to app/, lib/, config/, db/ — uncomment to customize:
  # c.dirs = %w[app lib config db]

  # The branch recorded in the report as this scan's git_branch, overriding
  # whatever `git rev-parse --abbrev-ref HEAD` finds locally (useful in CI
  # where checkouts often land in detached-HEAD state). Leave blank to use
  # the actual checked-out branch:
  # c.branch = ENV["CI_COMMIT_BRANCH"]

  # Silence a specific rule by rule_id (repeatable) — a known false positive
  # on this codebase, or a check that doesn't apply here. Prefer this over
  # deleting/editing the rule itself; run `bin/rails scryer:report` once and
  # check tmp/scryer_report.html's "Checks performed" section for the full
  # list of rule_ids:
  # c.skip_rules = %w[idor]

  # Any object/Proc responding to #call(prompt) (or #complete(prompt)) that
  # returns a String — opts into rewriting every finding's suggested_fix
  # against its actual code via that LLM. Off by default: no network calls,
  # no provider assumed. See the README's "AI-assisted fix suggestions" and
  # "AI-verified remediation" sections for what this does and how the
  # (optional) re-scan-to-confirm-the-fix-works verification works:
  # c.ai_client = ->(prompt) { MyLlmClient.complete(prompt) }
end

# Runtime query watcher (N+1 / unused eager loading — see README's "Runtime
# query watcher"). Off by default; uncomment to enable in this environment.
# Unlike the static scan above, this instruments a *running* app, so it's
# typically only turned on for development/test:
#
# if Rails.env.development? || Rails.env.test?
#   require "scryer/query_watcher"
#   Scryer::QueryWatcher.enable!
#   Rails.application.config.middleware.use Scryer::QueryWatcher::Middleware
# end
