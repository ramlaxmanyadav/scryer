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

      def scan
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
