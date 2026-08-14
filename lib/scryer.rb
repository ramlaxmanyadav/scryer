require "scryer/version"
require "scryer/ast"
require "scryer/finding"
require "scryer/rule_set"
require "scryer/rule"
require "scryer/method_extractor"
require "scryer/query_extractor"
require "scryer/cache_extractor"
require "scryer/duplicate_detector"
require "scryer/scanner"
require "scryer/report_renderer"
require "scryer/dependency_audit"
require "scryer/baseline"
require "scryer/ai_client"
require "scryer/fix_verifier"
require "scryer/ai_fix_suggester"

Dir[File.join(__dir__, "scryer", "rules", "*.rb")].sort.each { |f| require f }
Dir[File.join(__dir__, "scryer", "performance_rules", "*.rb")].sort.each { |f| require f }
Dir[File.join(__dir__, "scryer", "style_rules", "*.rb")].sort.each { |f| require f }

module Scryer
  class Configuration
    # `branch`, when set, overrides the git_branch value recorded in the
    # report (instead of the actual checked-out branch from `git rev-parse
    # --abbrev-ref HEAD`) — set this when the branch you want tracked isn't
    # necessarily the one the scan happens to run on (e.g. a CI runner in
    # detached-HEAD state, or you always want releases attributed to "main").
    #
    # `ai_client`, when set, opts into rewriting every finding's
    # `suggested_fix` via an LLM (see README's "AI-assisted fix
    # suggestions") — any object or Proc responding to #call(prompt) (or
    # #complete(prompt)). nil by default: off, no network calls, no
    # provider assumed.
    #
    # `skip_rules` silences specific checks by rule_id (e.g. a known false
    # positive on this codebase) without editing/removing the rule itself —
    # strings or symbols, matched against each Rule's rule_id. Empty by
    # default: every registered rule runs. The `scryer` executable's
    # `--skip RULE_ID` flag adds to this list for a single run rather than
    # replacing it.
    attr_accessor :project_name, :dirs, :branch, :ai_client, :skip_rules

    def initialize
      @dirs = Scryer::Scanner::DEFAULT_GLOB_DIRS
      @skip_rules = []
    end
  end

  class << self
    def configure
      yield configuration
    end

    def configuration
      @configuration ||= Configuration.new
    end

    # Runs the static scan with the current configuration (or explicit
    # overrides) applied, without needing to know Scanner's own constructor
    # shape. Exists mainly so the RSpec/Minitest test helpers (see
    # lib/scryer/rspec.rb / lib/scryer/minitest.rb) — and any other future
    # caller that just wants "the result of a normal scan" — don't each
    # duplicate `Scanner.new(root:, dirs:, skip_rules:).call`. The CLI/rake
    # task aren't changed to use this (they also handle dependency auditing,
    # baselines, and report writing inline) — this is for callers that only
    # need the static-scan Result itself.
    def scan(root:, dirs: configuration.dirs, skip_rules: configuration.skip_rules)
      Scryer::Scanner.new(root: root, dirs: dirs, skip_rules: skip_rules).call
    end
  end
end

# QueryWatcher instruments a *running* app (ActiveRecord query notifications,
# association reader hooks) rather than the one-shot static scan the rest of
# this file wires up, and is opt-in (Scryer::QueryWatcher.enable!) — so it
# isn't required eagerly here to avoid loading active_support/notifications
# machinery for the (default) case where nobody asked for it. Require it
# yourself where you call .enable! (see README's "Runtime query watcher").

require "scryer/railtie" if defined?(Rails::Railtie)
