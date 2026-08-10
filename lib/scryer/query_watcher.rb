require "set"

module Scryer
  # Runtime detector for two of the problems Bullet (github.com/flyerhzm/bullet)
  # is best known for — a collection query followed by one repeat query per
  # row ("N+1"), and an `.includes`/`.preload`/`.eager_load` association that
  # gets fetched but never actually read ("unused eager loading") — built
  # independently, on a different mechanism than Bullet's: SQL-shape
  # correlation via ActiveSupport::Notifications, plus a `Module#prepend` on
  # the two *public* entry points identified below (`QueryMethods#includes`
  # et al., and `Association#reader`), rather than Bullet's own per-request
  # association bookkeeping. No Bullet source was read or copied to build
  # this — see the README's "Runtime query watcher" section for the
  # conceptual write-up this was built from.
  #
  # Unlike the rest of Scryer (a one-shot static Ripper scan of source
  # files with no Rails required), this module instruments a *running* app:
  # it needs ActiveRecord loaded and real queries executing to find
  # anything. It does nothing until `Scryer::QueryWatcher.enable!` is
  # called (typically from an initializer, gated to non-production
  # environments — see README) and a scope is opened with `.watch { }` (the
  # Rack middleware below opens one per request automatically).
  class QueryWatcher
    Finding = Struct.new(:kind, :message, :call_site, :count, :suggested_fix, keyword_init: true) do
      def to_h
        super.transform_keys(&:to_s)
      end
    end

    # Everything this module needs to know about one request/job: which SQL
    # shapes ran from which call sites and how many times, which
    # associations got eager-loaded and from where, and which associations
    # were actually read. Scoped per-thread (see .watch) so concurrent
    # requests/jobs on different threads never share state.
    class Scope
      def initialize
        @query_shapes = Hash.new { |h, k| h[k] = Hash.new(0) } # shape => {call_site => count}
        @eager_loads = []      # [{owner:, association:, call_site:}]
        @accessed = Set.new    # "OwnerClass#association" strings
      end

      def record_query(shape, call_site)
        @query_shapes[shape][call_site] += 1
      end

      def record_eager_load(owner, association, call_site)
        @eager_loads << { owner: owner, association: association, call_site: call_site }
      end

      def record_access(owner, association)
        @accessed << "#{owner}##{association}"
      end

      def findings(n_plus_one_threshold:)
        n_plus_one_findings(n_plus_one_threshold) + unused_eager_load_findings
      end

      private

      def n_plus_one_findings(threshold)
        out = []
        @query_shapes.each_value do |by_site|
          by_site.each do |call_site, count|
            next if count < threshold

            out << Finding.new(
              kind: "n_plus_one_query_runtime",
              message: "The same query shape ran #{count} times from one call site during this " \
                        "request/job — consistent with an N+1 (a collection loaded once, then this " \
                        "query re-ran once per row instead of being eager-loaded).",
              call_site: call_site,
              count: count,
              suggested_fix: "If the code at #{call_site} loops over a collection and this query " \
                              "runs once per item, eager-load the association the loop reads instead " \
                              "(`.includes(:the_association)`, or `.preload`/`.eager_load`) on the " \
                              "query that produced the collection, so it's fetched once instead of " \
                              "once per row."
            )
          end
        end
        out
      end

      def unused_eager_load_findings
        @eager_loads.reject { |e| @accessed.include?("#{e[:owner]}##{e[:association]}") }.map do |e|
          Finding.new(
            kind: "unused_eager_load",
            message: "#{e[:owner]} eager-loaded `:#{e[:association]}` but it was never read during " \
                      "this request/job.",
            call_site: e[:call_site],
            count: 1,
            suggested_fix: "Drop `:#{e[:association]}` from the `.includes`/`.preload`/`.eager_load` " \
                            "call at #{e[:call_site]} — it's fetched every time but unused here, so " \
                            "it's an extra query (or an extra JOIN) for nothing. If it's only used on " \
                            "some code paths, consider eager-loading it there instead."
          )
        end
      end
    end

    class << self
      # Turns the watcher on for the life of the process. Idempotent — safe
      # to call more than once (later calls are no-ops). `logger` receives a
      # warning line per finding as it's detected; `n_plus_one_threshold` is
      # how many repeats of the same query shape from the same call site
      # count as N+1 (default 2 — the *second* occurrence is already one
      # more than a single collection load needs).
      def enable!(logger: nil, n_plus_one_threshold: 2)
        return if @enabled

        @logger = logger || default_logger
        @n_plus_one_threshold = n_plus_one_threshold
        @enabled = true

        require "active_support/notifications"
        subscribe_to_queries
        patch_active_record
      end

      def enabled?
        !!@enabled
      end

      # Opens a fresh per-thread scope, runs the block, then reports (and
      # returns) whatever was found. The bundled Rack middleware calls this
      # once per request; call it directly to watch a Sidekiq job, a rake
      # task, or anything else that isn't an HTTP request.
      def watch
        raise "Scryer::QueryWatcher.enable! was never called" unless enabled?

        previous = Thread.current[:scryer_query_watcher_scope]
        scope = Thread.current[:scryer_query_watcher_scope] = Scope.new
        yield
        report(scope)
      ensure
        Thread.current[:scryer_query_watcher_scope] = previous
      end

      def current_scope
        Thread.current[:scryer_query_watcher_scope]
      end

      def call_site
        loc = caller_locations.find { |l| !l.path.include?("/gems/") && !l.path.include?("lib/scryer/") }
        loc ? "#{loc.path}:#{loc.lineno}" : "unknown"
      end

      private

      def default_logger
        if defined?(Rails) && Rails.respond_to?(:logger) && Rails.logger
          Rails.logger
        else
          require "logger"
          Logger.new($stdout)
        end
      end

      def report(scope)
        findings = scope.findings(n_plus_one_threshold: @n_plus_one_threshold)
        findings.each { |f| @logger.warn("[Scryer::QueryWatcher] #{f.kind}: #{f.message} (#{f.call_site})") }
        findings
      end

      def subscribe_to_queries
        ActiveSupport::Notifications.subscribe("sql.active_record") do |*args|
          scope = current_scope
          next unless scope

          event = ActiveSupport::Notifications::Event.new(*args)
          next if event.payload[:name] == "SCHEMA" || event.payload[:cached]

          shape = normalize_sql(event.payload[:sql])
          scope.record_query(shape, call_site) if shape
        end
      end

      # Scrubs literal values so e.g. `WHERE post_id = 1` and
      # `WHERE post_id = 2` normalize to the same shape — a deliberately
      # simple heuristic (strip quoted strings and standalone/$-prefixed
      # numbers), not a real SQL parser.
      def normalize_sql(sql)
        return nil unless sql

        sql.gsub(/'[^']*'/, "?").gsub(/\$?\b\d+\b/, "?").squeeze(" ").strip
      end

      def patch_active_record
        ActiveSupport.on_load(:active_record) { Scryer::QueryWatcher.send(:install_hooks) }
      end

      def install_hooks
        require "active_record"

        ActiveRecord::QueryMethods.prepend(EagerLoadTracking)
        ActiveRecord::Associations::CollectionAssociation.prepend(AccessTracking)
        ActiveRecord::Associations::SingularAssociation.prepend(AccessTracking)
      end
    end

    # Prepended onto ActiveRecord::QueryMethods (mixed into every Relation).
    # `includes`/`preload`/`eager_load` are the three public methods that
    # request eager loading — recording *here*, not by inspecting the SQL,
    # is what lets this tell "asked for but unused" apart from "never asked
    # for at all".
    module EagerLoadTracking
      %i[includes preload eager_load].each do |method_name|
        define_method(method_name) do |*args|
          scope = Scryer::QueryWatcher.current_scope
          if scope
            site = Scryer::QueryWatcher.call_site
            Array(args).flatten.each do |assoc|
              scope.record_eager_load(klass.name, assoc.to_s, site) if assoc.is_a?(Symbol) || assoc.is_a?(String)
            end
          end
          super(*args)
        end
      end
    end

    # Prepended onto both association classes. `reader` is the method the
    # generated association method (`post.comments`) actually calls (see
    # ActiveRecord::Associations::Builder::Association) — unlike
    # `load_target`, it fires on *every* access, preloaded or not, which is
    # exactly what "was this ever read" needs.
    module AccessTracking
      def reader
        scope = Scryer::QueryWatcher.current_scope
        scope&.record_access(owner.class.name, reflection.name.to_s)
        super
      end
    end

    # `use Scryer::QueryWatcher::Middleware` opens one scope per request so
    # findings are correlated per-request rather than pooling across the
    # whole process lifetime (which would make every N+1 look like it fired
    # "once", the first time, and never again).
    class Middleware
      def initialize(app)
        @app = app
      end

      def call(env)
        result = nil
        Scryer::QueryWatcher.watch { result = @app.call(env) }
        result
      end
    end
  end
end
