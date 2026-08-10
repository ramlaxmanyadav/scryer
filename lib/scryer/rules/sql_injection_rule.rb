module Scryer
  module Rules
    # Flags ActiveRecord finder/query methods called with a string argument
    # that contains interpolation (#{...}) — the classic Rails SQL injection
    # pattern, e.g. `Order.where("status = '#{params[:status]}'")`.
    # Parameterized/hash forms (`where(status: params[:status])`,
    # `where("status = ?", params[:status])`) are safe and not flagged.
    class SqlInjectionRule < Rule
      self.rule_id = "sql_injection"
      self.category = "security"
      self.default_severity = "critical"
      self.title = "Possible SQL injection via string interpolation"

      QUERY_METHODS = %w[
        where find_by find_by! order pluck select group having
        find_by_sql calculate exists? count
      ].freeze

      def scan
        findings = []

        Ast.each_node(sexp) do |node|
          next unless Ast.tagged?(node, :method_add_arg, :command, :command_call)

          receiver_and_name = Ast.call_name(inner_call_node(node))
          next unless receiver_and_name

          _receiver, method_name = receiver_and_name
          next unless QUERY_METHODS.include?(method_name)

          args = Ast.call_arguments(node)
          next if args.empty?

          first_arg = args.first
          next unless Ast.string_literal_has_interpolation?(first_arg)

          line = Ast.line_of(first_arg) || Ast.line_of(node)
          findings << finding(
            line: line,
            message: "`#{method_name}` is called with a string built via interpolation, " \
                     "which lets user-controlled input change the SQL executed.",
            suggested_fix: "Use a parameterized form instead, e.g. " \
                            "`#{method_name}(\"column = ?\", value)` or the hash form " \
                            "`#{method_name}(column: value)` — both let Active Record escape " \
                            "the value safely instead of interpolating it directly into SQL."
          )
        end

        findings
      end

      private

      # method_add_arg wraps [call_or_fcall_node, args_node] — call_name needs
      # the inner call/fcall/vcall node, not the method_add_arg wrapper itself.
      def inner_call_node(node)
        return node unless Ast.tagged?(node, :method_add_arg)

        node[1]
      end
    end
  end
end
