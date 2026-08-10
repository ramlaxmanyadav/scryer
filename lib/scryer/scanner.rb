require "ripper"
require "set"

module Scryer
  # Ties parsing + rules + duplicate detection together across a directory
  # tree. This is the one entry point both the `sentinel:scan` rake task and
  # any generator/CLI should call — everything else in this gem is a building
  # block this class composes.
  class Scanner
    DEFAULT_GLOB_DIRS = %w[app lib config db].freeze
    SKIP_DIR_SEGMENTS = %w[vendor node_modules tmp log .git spec test].freeze

    # Duplicate-code detection only makes sense within hand-written business
    # logic. Migrations in particular are mostly boilerplate (create_table /
    # t.string / t.integer calls) that normalize to near-identical token
    # streams and drown out real duplicates with false positives — so unlike
    # the security/performance rules (which still scan every file under
    # DEFAULT_GLOB_DIRS), duplicate detection is restricted to models,
    # controllers, helpers, and concerns (wherever they're nested).
    DUPLICATE_DETECTION_APP_SUBDIRS = %w[models controllers helpers].freeze

    # Query and cache-value duplicates use a slightly higher bar than whole
    # methods: they're much shorter fragments, so a coincidental match at the
    # method threshold (0.6) is more likely — see DuplicateDetector's shingle
    # comment for why short token streams are more sensitive to this.
    QUERY_SIMILARITY_THRESHOLD = 0.7
    CACHE_SIMILARITY_THRESHOLD = 0.7

    Result = Struct.new(:security_findings, :performance_findings, :duplicate_groups, :files_scanned, :parse_errors, keyword_init: true)

    # `skip_rules` silences specific checks by rule_id (e.g. a known false
    # positive on this codebase) without editing/removing the rule itself —
    # accepts strings or symbols, matched against Rule.rule_id.
    def initialize(root:, dirs: DEFAULT_GLOB_DIRS, skip_rules: [])
      @root = File.expand_path(root)
      @dirs = dirs
      @skip_rules = Set.new(skip_rules.map(&:to_s))
    end

    def call
      files = collect_files
      all_methods = []
      all_queries = []
      all_cache_calls = []
      security_findings = []
      performance_findings = []
      parse_errors = []

      files.each do |abs_path|
        rel_path = abs_path.sub(/\A#{Regexp.escape(@root)}\/?/, "")
        source = File.read(abs_path)

        sexp = begin
          Ripper.sexp(source)
        rescue StandardError => e
          parse_errors << { file: rel_path, error: e.message }
          nil
        end

        if sexp.nil?
          parse_errors << { file: rel_path, error: "Ripper could not parse this file (possibly a syntax error, or Ruby syntax newer than this gem's Ruby runtime supports)" } unless parse_errors.any? { |pe| pe[:file] == rel_path }
          next
        end

        RuleSet.all.each do |rule_class|
          next if @skip_rules.include?(rule_class.rule_id.to_s)

          bucket =
            case rule_class.category
            when "security" then security_findings
            when "performance" then performance_findings
            end
          next unless bucket

          bucket.concat(rule_class.new(file: rel_path, source: source, sexp: sexp).scan)
        end

        if duplicate_detection_target?(rel_path)
          all_methods.concat(MethodExtractor.extract(file: rel_path, source: source, sexp: sexp))
          all_queries.concat(QueryExtractor.extract(file: rel_path, source: source, sexp: sexp))
          all_cache_calls.concat(CacheExtractor.extract(file: rel_path, source: source, sexp: sexp))
        end
      end

      # Same computed value cached under the same key from multiple call
      # sites is normal (just reusing the cache). Only flag it when the
      # *keys* differ too — that's either a redundant cache entry or a key
      # that drifted out of sync with a copy-pasted sibling.
      cache_groups = DuplicateDetector.call(all_cache_calls, threshold: CACHE_SIMILARITY_THRESHOLD, kind: "cache_duplicate")
                                       .select { |g| g.members.map(&:cache_key).uniq.size > 1 }

      duplicate_groups =
        DuplicateDetector.call(all_methods, kind: "method_duplicate") +
        DuplicateDetector.call(all_queries, threshold: QUERY_SIMILARITY_THRESHOLD, kind: "query_duplicate") +
        cache_groups

      Result.new(
        security_findings: security_findings,
        performance_findings: performance_findings,
        duplicate_groups: duplicate_groups,
        files_scanned: files.size,
        parse_errors: parse_errors
      )
    end

    private

    def duplicate_detection_target?(relative_path)
      segments = relative_path.split("/")
      return true if segments.include?("concerns")

      segments[0] == "app" && DUPLICATE_DETECTION_APP_SUBDIRS.include?(segments[1])
    end

    def collect_files
      @dirs.flat_map { |dir| Dir.glob(File.join(@root, dir, "**", "*.rb")) }
           .reject do |path|
             # Only check segments of the path *relative to @root* — checking
             # the full absolute path would wrongly exclude a project simply
             # because some ancestor directory outside the project happens to
             # be named e.g. "tmp" or "test".
             relative = path.sub(/\A#{Regexp.escape(@root)}\/?/, "")
             SKIP_DIR_SEGMENTS.any? { |seg| relative.split("/").include?(seg) }
           end
           .sort
           .uniq
    end
  end
end
