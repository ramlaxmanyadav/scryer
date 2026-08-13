module Scryer
  module PerformanceRules
    # Flags `.save`/`.save!`/`.update`/`.update!`/`.update_attribute(s)` called
    # on the block variable inside a `.each`/`.each_with_index` loop — one
    # database write per iteration where a single bulk statement
    # (`update_all`/`insert_all`/`upsert_all`) could often do the same work in
    # one round-trip. Best-effort: this rule can't tell whether the
    # per-record operation is actually uniform enough to batch (e.g. distinct
    # values per row still need `update_all` with a `CASE`, or don't fit the
    # bulk-method shape at all) — it's a nudge to double check, not a
    # guarantee the loop is replaceable as-is.
    class InefficientSaveLoopRule < Rule
      self.rule_id = "inefficient_save_loop"
      self.category = "performance"
      self.default_severity = "warning"
      self.title = "Per-record save/update inside a loop"

      LOOP_METHODS = %w[each each_with_index].freeze
      # Genuinely argless in normal use — a bare `:call` node, never wrapped
      # by a method_add_arg, so matching this tag alone can't double-count.
      BARE_METHODS = %w[save save!].freeze
      # Always take an argument, so they only ever show up wrapped in
      # method_add_arg/command/command_call — matching only the wrapper
      # avoids double-counting the inner call node these wrap.
      ARG_METHODS = %w[update update! update_attribute update_attributes].freeze

      # `db/seeds.rb` (and the multi-file `db/seeds/*.rb` convention Rails
      # supports via `Rails.application.load_seed`) is a one-time, manually
      # run setup script, not a request-handling hot path — the whole
      # premise of this rule (per-record round-trips scale badly as load
      # grows) doesn't apply to a script a developer runs once at setup
      # time for a small, fixed reference dataset (roles, plans, countries,
      # ...). Flagging `roles.each { |r| r.save! }` there is just noise, so
      # this rule skips findings whose file is exactly this path or under
      # this directory. Deliberately file-path-based rather than trying to
      # infer "small dataset" from the AST (which isn't reliably knowable —
      # a seed file can still iterate a CSV of arbitrary size), and narrow
      # to this one well-known Rails convention rather than any file that
      # merely "looks like a script" elsewhere in the app.
      SEED_FILE = "db/seeds.rb"
      SEED_DIR_PREFIX = "db/seeds/"

      def scan
        return [] if seed_file?

        findings = []

        Ast.each_node(sexp) do |node|
          next unless Ast.tagged?(node, :method_add_block)

          call_node = node[1]
          _receiver, loop_method = Ast.call_name(call_node) || [nil, nil]
          next unless LOOP_METHODS.include?(loop_method)

          block_node = node[2]
          param_name = block_param_name(block_node)
          next unless param_name

          find_save_calls(block_node[2], param_name).each do |line, method_name|
            findings << finding(
              line: line,
              message: "Inside a `.each` loop, `.#{method_name}` runs once per record — each call " \
                        "is a separate database round-trip, which scales linearly with the number " \
                        "of records instead of running as one bulk statement.",
              suggested_fix: "If every record gets the same update, replace the loop with " \
                              "`Model.where(...).update_all(column: value)` (one UPDATE for the whole " \
                              "set). If each record's new values differ but come from data already " \
                              "in hand, `upsert_all`/`insert_all` with an array of attribute hashes " \
                              "can also replace the per-row round-trips."
            )
          end
        end

        findings
      end

      private

      # `Scanner` builds `file` by globbing `File.join(root, dir, "**", "*.rb")`
      # with `dir` defaulting to `"."`, so the relative path it hands rules is
      # actually `"./db/seeds.rb"`, not `"db/seeds.rb"` — a plain `==`/
      # `start_with?` against the un-prefixed string silently never matches
      # against a real scan (verified: without stripping the prefix here,
      # `db/seeds.rb` still fired in a real `Scryer::Scanner.new(root:,
      # dirs: ["."]).call` run). Strip a leading `./` before comparing so
      # this matches how the path actually arrives, not an assumed form.
      def seed_file?
        normalized = file.to_s.delete_prefix("./")
        normalized == SEED_FILE || normalized.start_with?(SEED_DIR_PREFIX)
      end

      def block_param_name(block_node)
        return nil unless Ast.tagged?(block_node, :do_block, :brace_block)

        block_var = block_node[1]
        return nil unless Ast.tagged?(block_var, :block_var)

        params = block_var[1]
        first_param = params.is_a?(Array) ? params[1]&.first : nil
        return nil unless first_param.is_a?(Array) && first_param[0] == :@ident

        first_param[1]
      end

      def block_var_receiver?(node, param_name)
        return false unless Ast.tagged?(node, :var_ref, :vcall)

        inner = node[1]
        inner.is_a?(Array) && %i[@ident @ivar].include?(inner[0]) && inner[1] == param_name
      end

      def find_save_calls(body, param_name)
        results = []

        Ast.each_node(body) do |n|
          if Ast.tagged?(n, :call)
            name = Ast.ident_text(n[3])
            next unless BARE_METHODS.include?(name)
            next unless block_var_receiver?(n[1], param_name)

            results << [Ast.line_of(n), name]
          elsif Ast.tagged?(n, :method_add_arg, :command, :command_call)
            inner = Ast.tagged?(n, :method_add_arg) ? n[1] : n
            receiver_and_name = Ast.call_name(inner)
            next unless receiver_and_name

            receiver, name = receiver_and_name
            next unless ARG_METHODS.include?(name)
            next unless block_var_receiver?(receiver, param_name)

            results << [Ast.line_of(n), name]
          end
        end

        results
      end
    end
  end
end
