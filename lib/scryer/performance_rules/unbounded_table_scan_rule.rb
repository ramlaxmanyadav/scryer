module Scryer
  module PerformanceRules
    # Flags `Model.all.each`/`Model.where(...).each` (or `.order(...).each`) —
    # chaining `.each` directly onto a query loads every matching row into
    # memory at once before iterating. `find_each`/`find_in_batches` load and
    # yield records in bounded batches instead, keeping memory flat regardless
    # of table size. This only looks at the literal chain (`Const.query.each`)
    # so it won't catch the same problem one step removed — e.g. a variable
    # assigned from the query and iterated later (that pattern is out of scope
    # here; see `NPlusOneQueryRule`, which does track simple local
    # assignments, for a related check on what happens *inside* such a loop).
    class UnboundedTableScanRule < Rule
      self.rule_id = "unbounded_table_scan"
      self.category = "performance"
      self.default_severity = "warning"
      self.title = "Full query result loaded into memory before iterating"

      QUERY_METHODS = %w[all where order].freeze

      def scan
        findings = []

        Ast.each_node(sexp) do |node|
          next unless Ast.tagged?(node, :method_add_block)

          call_node = node[1]
          receiver, method_name = Ast.call_name(call_node) || [nil, nil]
          next unless method_name == "each"
          next unless receiver
          next unless direct_query_chain?(receiver)

          line = Ast.line_of(call_node)
          findings << finding(
            line: line,
            message: "`.each` is chained directly onto a query — Active Record loads every " \
                      "matching row into memory before the block runs even once, which can exhaust " \
                      "memory (or just be very slow) once the table is large.",
            suggested_fix: "Use `find_each` (row-by-row, fixed batch size) or `find_in_batches` " \
                            "(access a batch `Array` at a time) instead of `.each`, e.g. " \
                            "`Model.where(...).find_each { |record| ... }` — Active Record loads and " \
                            "discards records in bounded batches instead of all at once."
          )
        end

        findings
      end

      private

      def direct_query_chain?(receiver)
        return false unless receiver.is_a?(Array)

        inner = Ast.tagged?(receiver, :method_add_arg) ? receiver[1] : receiver
        return false unless Ast.tagged?(inner, :call)

        _, name = Ast.call_name(inner)
        return false unless QUERY_METHODS.include?(name)

        root = root_of(receiver)
        return false unless Ast.tagged?(root, :var_ref, :vcall)

        const = root[1]
        const.is_a?(Array) && const[0] == :@const
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
