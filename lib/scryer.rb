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
require "scryer/ai_client"
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
  end
end

# QueryWatcher instruments a *running* app (ActiveRecord query notifications,
# association reader hooks) rather than the one-shot static scan the rest of
# this file wires up, and is opt-in (Scryer::QueryWatcher.enable!) — so it
# isn't required eagerly here to avoid loading active_support/notifications
# machinery for the (default) case where nobody asked for it. Require it
# yourself where you call .enable! (see README's "Runtime query watcher").

require "scryer/railtie" if defined?(Rails::Railtie)
