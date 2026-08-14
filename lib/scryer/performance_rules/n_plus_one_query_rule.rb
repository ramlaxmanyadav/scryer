module Scryer
  module PerformanceRules
    # Flags likely N+1 queries: inside a `.each`/`.map` block whose receiver
    # looks like an Active Record collection (a local variable previously
    # assigned from `Model.where(...)`/`Model.all`/`Model.find(...)`, or a bare
    # instance variable — the common `@orders.each do |order| ... end` shape),
    # a bare no-arg `.method_name` call directly on the block variable (likely
    # an association access, e.g. `order.line_items`) is flagged unless an
    # `.includes(:that_name)` appeared earlier in the same base query chain.
    #
    # This is a heuristic, not type inference: it can't tell an association
    # read (`order.line_items`, which issues a query per row) from a plain
    # attribute/column read (`order.status`) or a harmless Ruby method call —
    # both parse identically as a bare no-arg call on the block variable. A
    # small block-list of universally-common non-association methods
    # (to_s, present?, class, ...) cuts down the noisiest false positives, but
    # real false positives on attribute reads are still expected and normal
    # for this class of tool (see README).
    class NPlusOneQueryRule < Rule
      self.rule_id = "n_plus_one_query"
      self.category = "performance"
      self.default_severity = "warning"
      self.title = "Possible N+1 query inside a loop"
      self.confidence = "medium"

      QUERY_METHODS = %w[where all find find_by find_by! order limit].freeze
      LOOP_METHODS = %w[each map collect each_with_index].freeze

      # Bare methods that are overwhelmingly plain Ruby/attribute reads rather
      # than association traversal — flagging these would be mostly noise.
      NON_ASSOCIATION_METHODS = %w[
        to_s to_i to_a to_h inspect class dup clone freeze frozen? hash
        present? blank? nil? empty? any? id id_value == equal? try tap then
        is_a? kind_of? instance_of? respond_to? send public_send object_id
        itself
      ].freeze

      def scan
        findings = []

        Ast.each_node(sexp) do |node|
          next unless Ast.tagged?(node, :def, :defs)

          body = node.last
          bindings = query_bindings(body)

          Ast.each_node(body) do |block_call|
            next unless Ast.tagged?(block_call, :method_add_block)

            call_node = block_call[1]
            receiver, loop_method = Ast.call_name(call_node) || [nil, nil]
            next unless LOOP_METHODS.include?(loop_method)
            next unless receiver

            base_name = var_or_ivar_name(receiver)
            next unless base_name

            includes = if bindings.key?(base_name)
                         bindings[base_name]
                       elsif base_name.start_with?("@")
                         [] # ivar set elsewhere — treat as an AR collection with no known eager-loading
                       end
            next unless includes # local var we never saw assigned from a query — don't guess

            block_node = block_call[2]
            param_name = block_param_name(block_node)
            next unless param_name

            findings.concat(association_calls(block_node[2], param_name, includes))
          end
        end

        findings
      end

      private

      # Local-variable/ivar assignments in this method whose value is a query
      # chain rooted at a bare Model constant, mapped to the set of association
      # names already eager-loaded via `.includes(...)` in that same chain.
      def query_bindings(body)
        bindings = {}

        Ast.each_node(body) do |node|
          next unless Ast.tagged?(node, :assign)

          name = assign_target_name(node[1])
          next unless name

          value = node[2]
          next unless query_chain?(value)

          bindings[name] = includes_symbols(value)
        end

        bindings
      end

      def assign_target_name(target)
        return nil unless Ast.tagged?(target, :var_field)

        inner = target[1]
        return nil unless inner.is_a?(Array)

        inner[1] if %i[@ident @ivar].include?(inner[0])
      end

      def query_chain?(value)
        root = root_of(value)
        return false unless Ast.tagged?(root, :var_ref, :vcall)

        const = root[1]
        return false unless const.is_a?(Array) && const[0] == :@const

        Ast.each_node(value).any? do |n|
          next false unless Ast.tagged?(n, :call, :method_add_arg, :command, :vcall, :fcall)

          inner = Ast.tagged?(n, :method_add_arg) ? n[1] : n
          name = Ast.call_name(inner)&.last
          QUERY_METHODS.include?(name)
        end
      end

      def includes_symbols(value)
        names = []

        Ast.each_node(value) do |n|
          next unless Ast.tagged?(n, :method_add_arg)

          receiver_and_name = Ast.call_name(n[1])
          next unless receiver_and_name && receiver_and_name.last == "includes"

          Ast.call_arguments(n).each do |arg|
            sym = symbol_name(arg)
            names << sym if sym
          end
        end

        names
      end

      def symbol_name(node)
        return nil unless Ast.tagged?(node, :symbol_literal)

        # symbol_literal wraps [:symbol, [:@ident, name, pos]] — one more
        # level of unwrapping than a bare @ident node.
        wrapper = node[1]
        return nil unless Ast.tagged?(wrapper, :symbol)

        ident = wrapper[1]
        return nil unless ident.is_a?(Array)

        ident[1] if %i[@ident @const @kw].include?(ident[0])
      end

      # Walks down the leftmost receiver chain of a call expression to find
      # the root object the whole chain is called on.
      def root_of(node)
        return node unless node.is_a?(Array)

        case node[0]
        when :method_add_arg, :call, :command_call
          root_of(node[1])
        else
          node
        end
      end

      def var_or_ivar_name(node)
        return nil unless Ast.tagged?(node, :var_ref, :vcall)

        inner = node[1]
        return nil unless inner.is_a?(Array)

        inner[1] if %i[@ident @ivar].include?(inner[0])
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

      def association_calls(body, param_name, includes)
        results = []

        Ast.each_node(body) do |n|
          next unless Ast.tagged?(n, :call)

          receiver = n[1]
          next unless var_or_ivar_name(receiver) == param_name

          method_name = Ast.ident_text(n[3])
          next unless method_name
          next if NON_ASSOCIATION_METHODS.include?(method_name)
          next if includes.include?(method_name)

          line = Ast.line_of(n)
          results << finding(
            line: line,
            message: "`#{param_name}.#{method_name}` is called inside a loop — if `#{method_name}` " \
                      "is an association, this issues a separate query per iteration instead of one " \
                      "batched query (a classic N+1).",
            suggested_fix: "Eager-load the association on the base query before the loop, e.g. " \
                            "`#{param_name.chomp('s')}s = Model.includes(:#{method_name}).where(...)` " \
                            "(or add `:#{method_name}` to an existing `.includes(...)` call), so Rails " \
                            "fetches it in one extra query instead of one per record."
          )
        end

        results
      end
    end
  end
end
