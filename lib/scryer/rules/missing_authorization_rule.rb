module Scryer
  module Rules
    # Flags a `*Controller` class that defines `create`/`update`/`destroy`
    # (Rails' three standard write actions) with NO authorization evidence
    # anywhere in the class — broader than IdorRule, which only fires when
    # there's also a params-derived `Model.find` call in the same class.
    # Plenty of write actions don't call `.find` at all (`Model.create(...)`
    # needs no lookup; a `destroy` might act on an object set up in a
    # `before_action`), so IdorRule's narrower pattern misses them even
    # though "this write action has no visible authorization check at all"
    # is exactly as real a concern. Restricted to the three standard write
    # actions (not every public method) specifically to avoid flagging
    # genuinely public controllers (a marketing page, a login form) that
    # have no write actions at all and legitimately need no authorization —
    # a controller that defines `create`/`update`/`destroy` at all is
    # already a much stronger "this manages a real resource" signal than
    # any action name would be.
    #
    # Expect overlap with `idor` on controllers that both `.find` a record
    # AND have no authorization — that's two different rules independently
    # confirming the same underlying gap from two different code shapes
    # (a lookup vs. a write action), not double-counting a bug.
    class MissingAuthorizationRule < Rule
      self.rule_id = "missing_authorization"
      self.category = "security"
      self.default_severity = "warning"
      self.title = "Write action with no visible authorization check"
      self.cwe = "CWE-862"
      self.owasp_category = "A01:2021-Broken Access Control"
      self.confidence = "low"

      WRITE_ACTIONS = %w[create update destroy].freeze

      # Duplicated from IdorRule intentionally, same as NON_MODEL_RECEIVERS
      # is duplicated between IdorRule and MassAssignmentRule — a small,
      # stable list not worth a shared-module indirection for two callers.
      AUTHORIZATION_METHODS = %w[
        authorize authorize! policy_scope can? cannot?
        load_and_authorize_resource authorize_resource
        verify_authorized verify_policy_scoped
      ].freeze

      def scan
        findings = []

        Ast.each_node(sexp) do |node|
          next unless Ast.tagged?(node, :class)

          class_name = Ast.class_name(node[1])
          next unless class_name.to_s.end_with?("Controller")

          body = node[3]
          next if each_call_names(body).any? { |name| AUTHORIZATION_METHODS.include?(name) }

          each_write_action_def(body).each do |def_node, action_name|
            findings << finding(
              line: Ast.line_of(def_node),
              message: "`#{class_name}##{action_name}` writes data (a standard Rails write " \
                        "action), and `#{class_name}` has no visible authorization check anywhere " \
                        "in it (no `authorize`, `policy_scope`, `can?`/`cannot?`, or CanCanCan/" \
                        "Pundit callback) — any logged-in (or, if this controller skips " \
                        "authentication too, any) user may be able to call this action.",
              suggested_fix: "Add an explicit authorization check before the write happens — " \
                              "`authorize @thing` (Pundit) or `authorize! :#{action_name}, @thing` " \
                              "(CanCanCan) — or `load_and_authorize_resource`/`after_action " \
                              ":verify_authorized` at the class level if every action here should " \
                              "be gated the same way."
            )
          end
        end

        findings
      end

      private

      # Same "call name or literal symbol/string argument" gathering as
      # IdorRule#each_call_names — see that method's comment for why the
      # argument half matters (Pundit's verify_authorized/verify_policy_scoped
      # are registered as before_action/after_action callback names, not
      # called directly).
      def each_call_names(node)
        Ast.each_node(node).flat_map do |n|
          next [] unless Ast.tagged?(n, :method_add_arg, :command, :command_call, :fcall, :vcall)

          inner = Ast.tagged?(n, :method_add_arg) ? n[1] : n
          name = Ast.call_name(inner)&.last
          arg_names = Ast.call_arguments(n).filter_map { |a| Ast.literal_text(a) }
          [name, *arg_names].compact
        end
      end

      def each_write_action_def(body)
        Ast.each_node(body).filter_map do |n|
          next unless Ast.tagged?(n, :def)

          name = Ast.ident_text(n[1])
          [n, name] if WRITE_ACTIONS.include?(name)
        end
      end
    end
  end
end
