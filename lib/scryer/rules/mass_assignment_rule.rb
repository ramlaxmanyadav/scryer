# frozen_string_literal: true
module Scryer
  module Rules
    # Flags `Model.new(params[...])` / `Model.new(params)` / `.update(params[...])`
    # / `.assign_attributes(params)` where the argument is `params` (or a
    # subscript of it) with no `.permit(...)` anywhere in the same argument
    # expression — i.e. attributes are being mass-assigned straight from the
    # request with no allow-list. "Is the receiver actually an ActiveRecord
    # model" is answered by Ast.likely_model_name? (known_models/
    # known_non_models, resolved once per scan by Scanner from every
    # `class X < Y` declaration it saw — see its own doc comment) — this
    # rule only supplies the receiver-shape acceptance itself (a bare
    # constant, an implicit receiver, or an ivar for the update-style verbs).
    class MassAssignmentRule < Rule
      self.rule_id = "mass_assignment"
      self.category = "security"
      self.default_severity = "critical"
      self.title = "Unpermitted mass assignment from params"
      self.cwe = "CWE-915"
      self.owasp_category = "A08:2021-Software and Data Integrity Failures"
      self.confidence = "medium"

      ASSIGNMENT_METHODS = %w[new create create! update update! assign_attributes attributes=].freeze

      # `update`/`update!`/`assign_attributes`/`attributes=` on an instance
      # variable (`@order.update(params[:order])`) is at least as common a
      # real-world shape as `Model.new(...)`/`Model.create(...)` on a bare
      # constant — the standard `before_action :set_thing` + `@thing.update`
      # scaffold pattern — but was invisible to this rule entirely until
      # found via the accuracy benchmark (benchmark/corpus.rb's
      # "mass_assignment" vulnerable sample), since likely_model_receiver?
      # only accepted a bare constant or implicit (nil) receiver. `.new`/
      # `create`/`create!` deliberately stay constant/nil-only: those verbs
      # only make sense as a receiver-less/class-level call in normal Rails
      # code, whereas an ivar could just as easily be a plain Hash (`Hash#
      # update` is a real `merge!` alias) — restricting the ivar allowance to
      # only the update-style verbs keeps this from also matching things like
      # `@filters.update(params[:filters])` on a Hash.
      IVAR_RECEIVER_METHODS = %w[update update! assign_attributes attributes=].freeze

      def scan
        findings = []

        Ast.each_node(sexp) do |node|
          next unless Ast.tagged?(node, :method_add_arg, :command, :command_call)

          inner = Ast.tagged?(node, :method_add_arg) ? node[1] : node
          receiver_and_name = Ast.call_name(inner)
          next unless receiver_and_name

          receiver, method_name = receiver_and_name
          next unless ASSIGNMENT_METHODS.include?(method_name)
          next unless likely_model_receiver?(receiver, method_name)

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
      # itself), a plain unnamespaced constant reference (`Order`) Ast.
      # likely_model_name? doesn't rule out, or — for the update-style
      # verbs only, see IVAR_RECEIVER_METHODS — an instance variable
      # (`@order`); false for namespaced constant paths (`BCrypt::Password`,
      # `Admin::Order` — a real gap, see mass_assignment_rule's class comment
      # and the benchmark corpus's "KNOWN LIMITATION" sample) or anything else.
      def likely_model_receiver?(receiver, method_name)
        return true if receiver.nil?
        return true if IVAR_RECEIVER_METHODS.include?(method_name) && ivar_receiver?(receiver)
        return false unless Ast.tagged?(receiver, :var_ref)

        const_node = receiver[1]
        return false unless const_node.is_a?(Array) && const_node[0] == :@const

        Ast.likely_model_name?(const_node[1], known_models: known_models, known_non_models: known_non_models)
      end

      def ivar_receiver?(node)
        Ast.tagged?(node, :var_ref) && node[1].is_a?(Array) && node[1][0] == :@ivar
      end

      # True if `node` references `params` (see Ast.references_params?)
      # without a `.permit`/`.permit!` call wrapping it (permit! is itself
      # flagged as unsafe too, so it doesn't count as "safe").
      def references_raw_params?(node)
        return false if has_permit_call?(node)

        Ast.references_params?(node)
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
