module Scryer
  module Rules
    # Flags `Model.new(params[...])` / `Model.new(params)` / `.update(params[...])`
    # / `.assign_attributes(params)` where the argument is `params` (or a
    # subscript of it) with no `.permit(...)` anywhere in the same argument
    # expression — i.e. attributes are being mass-assigned straight from the
    # request with no allow-list.
    class MassAssignmentRule < Rule
      self.rule_id = "mass_assignment"
      self.category = "security"
      self.default_severity = "critical"
      self.title = "Unpermitted mass assignment from params"

      ASSIGNMENT_METHODS = %w[new create create! update update! assign_attributes attributes=].freeze

      # Common stdlib/gem constants with their own `.new`/`.create`-style
      # factory methods that have nothing to do with ActiveRecord mass
      # assignment (e.g. `BCrypt::Password.create(params[:password])` is
      # hashing a single value, not setting a hash of model attributes).
      # Excluding these — plus anything referenced through a namespaced
      # `A::B` path, which real Rails models are less commonly called via at
      # the exact call site — cuts down false positives significantly.
      NON_MODEL_RECEIVERS = %w[
        Struct OpenStruct Data Class Module BCrypt OpenSSL Net URI Digest
        JSON YAML Marshal String Array Hash Integer Float Symbol Comparable
      ].freeze

      def scan
        findings = []

        Ast.each_node(sexp) do |node|
          next unless Ast.tagged?(node, :method_add_arg, :command, :command_call)

          inner = Ast.tagged?(node, :method_add_arg) ? node[1] : node
          receiver_and_name = Ast.call_name(inner)
          next unless receiver_and_name

          receiver, method_name = receiver_and_name
          next unless ASSIGNMENT_METHODS.include?(method_name)
          next unless likely_model_receiver?(receiver)

          args = Ast.call_arguments(node)
          next if args.empty?

          arg = args.first
          next unless references_raw_params?(arg)

          line = Ast.line_of(arg) || Ast.line_of(node)
          findings << finding(
            line: line,
            message: "`#{method_name}` receives `params` (or a subscript of it) directly, " \
                      "with no `.permit(...)` call — every attribute in the request can be " \
                      "set, including ones the form/API was never meant to expose (e.g. `admin`, `role_id`).",
            suggested_fix: "Wrap the params in a strong-parameters method, e.g. " \
                            "`#{method_name}(order_params)` with `def order_params; " \
                            "params.require(:order).permit(:status, :total); end` — only the " \
                            "explicitly permitted keys get through."
          )
        end

        findings
      end

      private

      # true for an implicit receiver (bare `create(...)` inside the model
      # itself) or a plain unnamespaced constant reference (`Order`) that
      # isn't a known non-model stdlib/gem constant; false for namespaced
      # constant paths (`BCrypt::Password`) or anything else.
      def likely_model_receiver?(receiver)
        return true if receiver.nil?
        return false unless Ast.tagged?(receiver, :var_ref)

        const_node = receiver[1]
        return false unless const_node.is_a?(Array) && const_node[0] == :@const

        !NON_MODEL_RECEIVERS.include?(const_node[1])
      end

      # True if `node` is `params`, `params[:x]`, or contains such a reference
      # without a `.permit`/`.permit!` call wrapping it (permit! is itself
      # flagged as unsafe too, so it doesn't count as "safe").
      def references_raw_params?(node)
        return false unless node.is_a?(Array)
        return false if has_permit_call?(node)

        Ast.each_node(node).any? do |n|
          Ast.tagged?(n, :vcall, :var_ref, :fcall) && Ast.ident_text(n[1]) == "params"
        end
      end

      def has_permit_call?(node)
        Ast.each_node(node).any? do |n|
          next false unless Ast.tagged?(n, :call, :method_add_arg)

          inner = Ast.tagged?(n, :method_add_arg) ? n[1] : n
          name = Ast.call_name(inner)&.last
          %w[permit permit!].include?(name)
        end
      end
    end
  end
end
