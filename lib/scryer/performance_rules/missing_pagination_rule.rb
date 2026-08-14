module Scryer
  module PerformanceRules
    # Flags a controller `index` action that loads `Model.all` or a bare
    # `Model.where(...)` (no `.limit`/`.page`/`.per`/`.paginate`/`.find_each`
    # bound anywhere in the chain) and hands the result straight to an
    # instance variable or `render` — i.e. nothing bounds how many rows get
    # loaded and rendered. Heuristic: only looks at the literal call chain
    # text, not what happens to the variable afterwards (e.g. slicing it in
    # the view would not be detected as "safe" by this rule).
    class MissingPaginationRule < Rule
      self.rule_id = "missing_pagination"
      self.category = "performance"
      self.default_severity = "warning"
      self.title = "Possible unbounded result set on an index action"
      self.confidence = "medium"

      QUERY_METHODS = %w[all where].freeze
      BOUND_METHODS = %w[limit page per paginate find_each find_in_batches first take].freeze

      def scan
        findings = []

        Ast.each_node(sexp) do |node|
          next unless Ast.tagged?(node, :def)
          next unless Ast.ident_text(node[1]) == "index"

          body = node.last
          findings.concat(check_body(body))
        end

        findings
      end

      private

      def check_body(body)
        results = []
        seen_lines = []

        sink_values(body).each do |value|
          next unless unbounded_query?(value)

          line = Ast.line_of(value)
          next if seen_lines.include?(line)

          seen_lines << line
          results << finding(
            line: line,
            message: "The `index` action loads records with no `.limit`/`.page`/`.per` bound — " \
                      "as the table grows this action will load (and likely render) every row, " \
                      "getting slower and more memory-hungry over time.",
            suggested_fix: "Bound the result set, e.g. with Kaminari/will_paginate " \
                            "(`Model.page(params[:page]).per(25)`) or a plain `.limit(...)`, " \
                            "so the action's cost stays roughly constant as the table grows."
          )
        end

        results
      end

      # Collects the value expressions that end up as an ivar/local assignment
      # or a `render(...)` argument — the "sinks" an unbounded query could flow
      # into directly.
      def sink_values(body)
        values = []

        Ast.each_node(body) do |node|
          if Ast.tagged?(node, :assign) && assignable_target?(node[1])
            values << node[2]
          elsif render_call?(node)
            values.concat(flatten_arg_values(Ast.call_arguments(node)))
          end
        end

        values
      end

      def assignable_target?(target)
        return false unless Ast.tagged?(target, :var_field)

        inner = target[1]
        inner.is_a?(Array) && %i[@ident @ivar].include?(inner[0])
      end

      def render_call?(node)
        inner = Ast.tagged?(node, :method_add_arg) ? node[1] : node
        return false unless Ast.tagged?(inner, :command, :fcall, :call, :vcall, :command_call)

        Ast.call_name(inner)&.last == "render"
      end

      def flatten_arg_values(nodes)
        nodes.flat_map do |n|
          if Ast.tagged?(n, :bare_assoc_hash)
            n[1].filter_map { |assoc| Ast.tagged?(assoc, :assoc_new) ? assoc[2] : nil }
          else
            [n]
          end
        end
      end

      def unbounded_query?(value)
        return false unless value.is_a?(Array)

        root = root_of(value)
        return false unless Ast.tagged?(root, :var_ref, :vcall)

        const = root[1]
        return false unless const.is_a?(Array) && const[0] == :@const

        method_names = Ast.each_node(value).filter_map do |n|
          next unless Ast.tagged?(n, :call, :method_add_arg, :command, :vcall, :fcall)

          inner = Ast.tagged?(n, :method_add_arg) ? n[1] : n
          Ast.call_name(inner)&.last
        end

        (method_names & QUERY_METHODS).any? && (method_names & BOUND_METHODS).none?
      end

      def root_of(node)
        return node unless node.is_a?(Array)

        case node[0]
        when :method_add_arg, :call, :command_call
          root_of(node[1])
        else
          node
        end
      end
    end
  end
end
