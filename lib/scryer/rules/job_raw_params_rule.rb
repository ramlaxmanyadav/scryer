module Scryer
  module Rules
    # Flags `SomeJob.perform_async(...)` / `.perform_later(...)` /
    # `.perform_now(...)` (or the bare form inside the job's own class) where
    # an argument references `params` more broadly than a single-key
    # subscript — see raw_params_reference? below for exactly what's exempt
    # (`params[:id]` and friends) versus what isn't.
    #
    # Sidekiq stores job arguments in Redis in plaintext and displays them in
    # its web UI; both Sidekiq and ActiveJob log job arguments by default.
    # Passing a raw `params` hash risks leaking whatever it contains —
    # passwords, tokens, full user-submitted fields — into logs, Redis, and
    # the Sidekiq UI, instead of passing just the specific id/value the job
    # actually needs. This is a distinct, well-documented Sidekiq/ActiveJob
    # concern from mass assignment (which is about writing untrusted params
    # to a model, not about where params end up once queued).
    class JobRawParamsRule < Rule
      self.rule_id = "job_raw_params"
      self.category = "security"
      self.default_severity = "warning"
      self.title = "Raw params passed to a background job"
      self.cwe = "CWE-532"
      self.owasp_category = "A09:2021-Security Logging and Monitoring Failures"
      self.confidence = "medium"

      PERFORM_METHODS = %w[perform_async perform_later perform_now].freeze

      def scan
        findings = []

        Ast.each_node(sexp) do |node|
          next unless Ast.tagged?(node, :method_add_arg, :command, :command_call)

          inner = Ast.tagged?(node, :method_add_arg) ? node[1] : node
          receiver_and_name = Ast.call_name(inner)
          next unless receiver_and_name

          _receiver, method_name = receiver_and_name
          next unless PERFORM_METHODS.include?(method_name)

          args = Ast.call_arguments(node)
          next unless args.any? { |a| raw_params_reference?(a) }

          line = Ast.line_of(node)
          findings << finding(
            line: line,
            message: "`#{method_name}` is called with an argument that references `params` — " \
                      "Sidekiq stores job arguments in Redis in plaintext (visible in its web UI), " \
                      "and both Sidekiq and ActiveJob log job arguments by default, so anything in " \
                      "the raw params hash (passwords, tokens, other sensitive fields) can end up " \
                      "somewhere it wasn't meant to be readable.",
            suggested_fix: "Extract only the specific id/value(s) the job actually needs into " \
                            "local variables before enqueuing (e.g. `id = params[:id]; " \
                            "#{method_name}(id)`), instead of passing `params` (or a subscript of " \
                            "it) straight through, and have the job re-fetch/re-derive anything " \
                            "else it needs from that id."
          )
        end

        findings
      end

      private

      # True if `node`'s subtree references `params` in a way broader than a
      # narrow, controlled extraction — a bare `params` value, or `params` as
      # the receiver of anything other than `[]`, `.dig`, or `.permit`.
      #
      # `params[:id]` and `params.dig(:id)` are equivalent single-key
      # extractions (`ActionController::Parameters#dig` behaves like `#[]`
      # for one key, and digging through several keys still only ever
      # returns one scalar/sub-value, never the rest of the hash) — flagging
      # one but not the other would be an arbitrary inconsistency, not a
      # risk-based distinction. `params.permit(:id, :name)` (optionally
      # chained into `.to_h`/`.to_unsafe_h`/etc.) is Rails' own sanctioned
      # allowlisting idiom — MassAssignmentRule already accepts a `.permit`
      # call as sufficient sanitization elsewhere in this gem, so treating it
      # as still "raw" here would send a contradictory message about the
      # same idiom. None of this is zero-risk (a permitted field can still
      # be a name/email/phone; a dug-up value can still be a token) — but
      # flagging Rails' own recommended patterns here would just be noise
      # that erodes trust in every other finding this rule reports.
      # Everything else — bare `params`, `.to_json`, `.to_h`/`.to_unsafe_h`
      # with no preceding `.permit`, `.merge`, `.except`, ... — still flags,
      # since those really can carry the full, uncontrolled params payload.
      NARROW_PARAMS_METHODS = %w[dig permit].freeze

      def raw_params_reference?(node)
        found = false

        walk = lambda do |n|
          next if found || !n.is_a?(Array)

          if Ast.tagged?(n, :aref) && bare_params?(n[1])
            walk.call(n[2]) if n[2].is_a?(Array)
            next
          end

          if narrow_params_call?(n)
            next
          end

          if bare_params?(n)
            found = true
            next
          end

          n.each { |c| walk.call(c) if c.is_a?(Array) }
        end

        walk.call(node)
        found
      end

      def narrow_params_call?(node)
        return false unless Ast.tagged?(node, :method_add_arg, :call, :command_call)

        inner = Ast.tagged?(node, :method_add_arg) ? node[1] : node
        receiver_and_name = Ast.call_name(inner)
        return false unless receiver_and_name

        receiver, method_name = receiver_and_name
        bare_params?(receiver) && NARROW_PARAMS_METHODS.include?(method_name)
      end

      def bare_params?(node)
        Ast.tagged?(node, :vcall, :var_ref, :fcall) && Ast.ident_text(node[1]) == "params"
      end
    end
  end
end
