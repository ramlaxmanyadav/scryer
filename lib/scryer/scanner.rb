# frozen_string_literal: true
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

    # Real ActiveRecord model base classes — a class transitively inheriting
    # from one of these (see #model_via_chain?) goes into known_models.
    KNOWN_MODEL_BASE_CLASSES = %w[ApplicationRecord ActiveRecord::Base].freeze

    # Rails generates exactly one non-model "Application*" base class per
    # concern (ApplicationController, ApplicationJob, ApplicationMailer,
    # ApplicationCable::Connection/Channel) — ApplicationRecord is the only
    # one of that family that models actually inherit from. A class
    # inheriting from anything else matching this shape (including a
    # project's own equivalent, e.g. a hand-rolled `ApplicationService`)
    # can never also be an ActiveRecord model, regardless of what it's
    # named — see Ast.likely_model_name?'s known_non_models.
    NON_MODEL_SUPERCLASS_PATTERN = /\AApplication(?!Record\z)\w*\z/.freeze

    Result = Struct.new(:security_findings, :performance_findings, :style_findings, :duplicate_groups, :files_scanned, :parse_errors, keyword_init: true)

    # `skip_rules` silences specific checks by rule_id (e.g. a known false
    # positive on this codebase) without editing/removing the rule itself —
    # accepts strings or symbols, matched against Rule.rule_id.
    #
    # `detect_duplicates: false` skips duplicate-code detection entirely
    # (method/query/cache-key extraction and the DuplicateDetector passes
    # below) — unlike the security/performance/style rules, duplicate
    # detection isn't a `Scryer::Rule` with its own rule_id, so `skip_rules`
    # has no way to address it; this is its equivalent off switch. See
    # `Scryer::Configuration#detect_duplicates` for the config-driven default
    # every CLI/rake entry point reads before constructing a Scanner.
    def initialize(root:, dirs: DEFAULT_GLOB_DIRS, skip_rules: [], detect_duplicates: true)
      @root = File.expand_path(root)
      @dirs = dirs
      @skip_rules = Set.new(skip_rules.map(&:to_s))
      @detect_duplicates = detect_duplicates
    end

    def call
      files = collect_files
      parsed_files = []
      parse_errors = []

      # First pass: read + parse every file exactly once (cached in
      # parsed_files for the second pass below) and, while we're already
      # walking each file's sexp, collect every `class X < Y` declaration
      # into class_superclass/no_superclass_classes/application_family_classes
      # — the raw material #resolve_known_models/#resolve_known_non_models
      # turn into a real, project-wide "is this actually an ActiveRecord
      # model" signal (see Ast.likely_model_name?'s doc comment for why this
      # exists: a plain Ruby service/command object's `.new(params)` call
      # looks identical to a real model's, and no per-file view can tell
      # them apart — this can, because it's seen every class declaration in
      # the project before any rule runs). Has to be a separate pass from
      # rule-scanning below: a model declared in one file needs to be known
      # before an *earlier-processed* file's controller referencing it is
      # scanned, which a single combined pass can't guarantee regardless of
      # file processing order.
      class_superclass = {}
      no_superclass_classes = Set.new
      application_family_classes = Set.new

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

        parsed_files << [rel_path, source, sexp]
        collect_class_declarations(sexp, class_superclass, no_superclass_classes, application_family_classes)
      end

      known_models = resolve_known_models(class_superclass)
      known_non_models = no_superclass_classes | application_family_classes

      all_methods = []
      all_queries = []
      all_cache_calls = []
      security_findings = []
      performance_findings = []
      style_findings = []

      parsed_files.each do |rel_path, source, sexp|
        RuleSet.all.each do |rule_class|
          next if @skip_rules.include?(rule_class.rule_id.to_s)

          bucket =
            case rule_class.category
            when "security" then security_findings
            when "performance" then performance_findings
            when "style" then style_findings
            end
          next unless bucket

          bucket.concat(rule_class.new(file: rel_path, source: source, sexp: sexp,
                                        known_models: known_models, known_non_models: known_non_models).scan)
        end

        if @detect_duplicates && duplicate_detection_target?(rel_path)
          all_methods.concat(MethodExtractor.extract(file: rel_path, source: source, sexp: sexp))
          all_queries.concat(QueryExtractor.extract(file: rel_path, source: source, sexp: sexp))
          all_cache_calls.concat(CacheExtractor.extract(file: rel_path, source: source, sexp: sexp))
        end
      end

      duplicate_groups =
        if @detect_duplicates
          # Same computed value cached under the same key from multiple call
          # sites is normal (just reusing the cache). Only flag it when the
          # *keys* differ too — that's either a redundant cache entry or a
          # key that drifted out of sync with a copy-pasted sibling.
          cache_groups = DuplicateDetector.call(all_cache_calls, threshold: CACHE_SIMILARITY_THRESHOLD, kind: "cache_duplicate")
                                           .select { |g| g.members.map(&:cache_key).uniq.size > 1 }

          DuplicateDetector.call(all_methods, kind: "method_duplicate") +
            DuplicateDetector.call(all_queries, threshold: QUERY_SIMILARITY_THRESHOLD, kind: "query_duplicate") +
            cache_groups
        else
          []
        end

      Result.new(
        security_findings: security_findings,
        performance_findings: performance_findings,
        style_findings: style_findings,
        duplicate_groups: duplicate_groups,
        files_scanned: files.size,
        parse_errors: parse_errors
      )
    end

    private

    # Records one file's `class X < Y` (and `module X`) declarations into the
    # three accumulators #call builds across every scanned file.
    # `class_superclass` maps a class's own (last-segment) name to its
    # superclass's full name (kept full, not truncated, so e.g.
    # "ActiveRecord::Base" still matches KNOWN_MODEL_BASE_CLASSES exactly in
    # #model_via_chain? before that method truncates it to walk the chain
    # further). A class declared with literally no superclass (`class
    # Server; end`) goes straight into no_superclass_classes — no real
    # ActiveRecord model is ever declared that way, so this is an
    # unconditional, safe "definitely not a model" signal regardless of the
    # class's name. `module X` gets the same treatment for the same reason:
    # a bare Ruby module (e.g. this gem's own `RuleSet`) can never be an
    # ActiveRecord model either, which matters for rules like
    # UnboundedTableScanRule/NPlusOneQueryRule that otherwise treat any
    # `Const.all.each`-shaped call as a possible query on a model.
    def collect_class_declarations(sexp, class_superclass, no_superclass_classes, application_family_classes)
      Ast.each_node(sexp) do |node|
        if Ast.tagged?(node, :module)
          name = Ast.class_name(node[1])
          no_superclass_classes << last_segment(name) if name
          next
        end

        next unless Ast.tagged?(node, :class)

        name = Ast.class_name(node[1])
        next unless name

        last = last_segment(name)
        superclass_node = node[2]

        if superclass_node.nil?
          no_superclass_classes << last
          next
        end

        superclass_name = Ast.class_name(superclass_node)
        next unless superclass_name

        application_family_classes << last if superclass_name.match?(NON_MODEL_SUPERCLASS_PATTERN)
        class_superclass[last] = superclass_name
      end
    end

    # Every class name in class_superclass whose superclass chain
    # terminates in ApplicationRecord/ActiveRecord::Base, resolved
    # transitively (`class Order < ShardedRecord` + `class ShardedRecord <
    # ApplicationRecord` both scanned) — not just direct inheritance, so
    # e.g. a real Rails app's own abstract per-shard base classes, or STI
    # subclasses, are recognized as models too.
    def resolve_known_models(class_superclass)
      class_superclass.each_key.select { |name| model_via_chain?(name, class_superclass) }.to_set
    end

    # `seen` guards against an (invalid, but not this method's job to
    # reject) inheritance cycle recursing forever.
    def model_via_chain?(name, class_superclass, seen = Set.new)
      return false if seen.include?(name)

      seen << name
      superclass = class_superclass[name]
      return false unless superclass
      return true if KNOWN_MODEL_BASE_CLASSES.include?(superclass)

      next_name = last_segment(superclass)
      return false unless class_superclass.key?(next_name)

      model_via_chain?(next_name, class_superclass, seen)
    end

    def last_segment(name)
      name.to_s.split("::").last
    end

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
