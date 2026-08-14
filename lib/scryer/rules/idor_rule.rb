module Scryer
  module Rules
    # Flags `Model.find(params[...])` / `Model.find_by(...params...)` inside
    # a controller where the receiver is a bare, unnamespaced constant (not
    # scoped through e.g. `current_user.things.find(...)`) and no
    # authorization call (`authorize`, `authorize!`, `policy_scope`, `can?`,
    # `cannot?` — the common Pundit/CanCanCan method names) appears anywhere
    # else in the same controller class.
    #
    # This is the least precise rule in the gem, by nature of the problem:
    # whether a given `find` is actually scoped to the current user is a
    # question about the whole app's authorization model, not something
    # visible from one file's AST. Expect real false positives — e.g. an
    # admin-only controller already gated by a class-level `before_action`,
    # or a genuinely global/unowned model (`Country.find(params[:id])`).
    # Treat every finding as "worth a second look," not a confirmed bug —
    # same spirit as CsrfProtectionRule's class-wide safeguard check, applied
    # to a harder problem.
    class IdorRule < Rule
      self.rule_id = "idor"
      self.category = "security"
      self.default_severity = "warning"
      self.title = "Possible insecure direct object reference (IDOR)"
      self.cwe = "CWE-639"
      self.owasp_category = "A01:2021-Broken Access Control"
      self.confidence = "low"

      FINDER_METHODS = %w[find find_by find_by!].freeze

      # Same reasoning as MassAssignmentRule::NON_MODEL_RECEIVERS: common
      # stdlib/gem constants with their own `.find`-style methods that have
      # nothing to do with an ActiveRecord model lookup.
      NON_MODEL_RECEIVERS = %w[
        Struct OpenStruct Data Class Module BCrypt OpenSSL Net URI Digest
        JSON YAML Marshal String Array Hash Integer Float Symbol Comparable
        Enumerable File Dir
      ].freeze

      # Pundit's `authorize`/`policy_scope`/`can?`/`cannot?` plus two more
      # well-established framework-provided safeguards, deliberately not an
      # attempt at an exhaustive list of every app's custom guard method
      # (e.g. a homegrown `require_admin!` before_action) — this rule's own
      # documented limitation above already covers that case as expected
      # noise, since there's no reliable way to know a custom method name
      # actually performs record-level authorization rather than something
      # unrelated:
      #   - `load_and_authorize_resource` / `authorize_resource` — CanCanCan's
      #     own controller macros; declaring either one authorizes every
      #     action in the controller (the same effect as calling `authorize!`
      #     in each action by hand), so a controller using it has the same
      #     safeguard this rule already accepts for a manual `authorize!` call.
      #   - `verify_authorized` / `verify_policy_scoped` — Pundit's own
      #     safety-net `after_action` callbacks (`after_action
      #     :verify_authorized`), which raise unless some `authorize`/
      #     `policy_scope` call already happened during the action. A
      #     controller using this callback is *more* rigorously guarded than
      #     one with a bare `authorize` call, not less.
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

          each_unscoped_find(body).each do |find_node, method_name|
            line = Ast.line_of(find_node)
            findings << finding(
              line: line,
              message: "`#{method_name}` looks up a record directly from `params`, and " \
                        "`#{class_name}` has no visible authorization check (no `authorize`, " \
                        "`policy_scope`, or `can?`/`cannot?` anywhere in it) — if this record " \
                        "belongs to a specific user/account, another user may be able to view or " \
                        "modify it just by changing the id in the request.",
              suggested_fix: "Scope the lookup to the current actor instead of the bare model, " \
                              "e.g. `current_user.things.#{method_name}(params[:id])`, or add an " \
                              "explicit authorization check (`authorize @thing` for Pundit, " \
                              "`authorize! :show, @thing` for CanCanCan) before using the record."
            )
          end
        end

        findings
      end

      private

      # Gathers both the call's own method name (`authorize` in `authorize
      # @thing`, `load_and_authorize_resource` in the bare macro call) *and*
      # any literal symbol/string arguments passed to it (`verify_authorized`
      # in `after_action :verify_authorized`) — Pundit's `verify_authorized`/
      # `verify_policy_scoped` safeguards are registered as callback names
      # via `before_action`/`after_action`, not invoked directly, so checking
      # only the enclosing call's name would miss them entirely.
      def each_call_names(node)
        Ast.each_node(node).flat_map do |n|
          next [] unless Ast.tagged?(n, :method_add_arg, :command, :command_call, :fcall, :vcall)

          inner = Ast.tagged?(n, :method_add_arg) ? n[1] : n
          name = Ast.call_name(inner)&.last
          arg_names = Ast.call_arguments(n).filter_map { |a| Ast.literal_text(a) }
          [name, *arg_names].compact
        end
      end

      def each_unscoped_find(body)
        Ast.each_node(body).filter_map do |node|
          next unless Ast.tagged?(node, :method_add_arg, :command, :command_call)

          inner = Ast.tagged?(node, :method_add_arg) ? node[1] : node
          receiver_and_name = Ast.call_name(inner)
          next unless receiver_and_name

          receiver, method_name = receiver_and_name
          next unless FINDER_METHODS.include?(method_name)
          next unless likely_model_receiver?(receiver)

          args = Ast.call_arguments(node)
          next unless args.any? { |a| Ast.references_params?(a) }

          [node, method_name]
        end
      end

      # A namespaced model (`Admin::Post.find(...)`, `Api::V1::User.find(...)`
      # — a common real-world pattern for admin-scoped or API-versioned
      # resources) parses as `:const_path_ref`, not `:var_ref` — verified via
      # `Ripper.sexp("Admin::Post.find(params[:id])")`. The original version
      # of this check only handled bare `:var_ref` receivers, so a
      # namespaced model's `.find(params[...])` was silently never examined
      # at all (a false negative, not a false positive — worth fixing since
      # namespacing under a module is an extremely common Rails convention).
      # Checked against the *last* segment (`"Post"`, not `"Admin"`), same
      # exclusion list either way — none of NON_MODEL_RECEIVERS are commonly
      # used in namespaced form for this purpose, but checking the actual
      # class name being looked up is the more correct match regardless.
      def likely_model_receiver?(receiver)
        return false if receiver.nil? # bare find(...) inside the model itself, not a controller lookup

        const_name = const_receiver_name(receiver)
        return false unless const_name

        !NON_MODEL_RECEIVERS.include?(const_name)
      end

      def const_receiver_name(node)
        if Ast.tagged?(node, :var_ref) && node[1].is_a?(Array) && node[1][0] == :@const
          node[1][1]
        elsif Ast.tagged?(node, :const_path_ref) && node[2].is_a?(Array) && node[2][0] == :@const
          node[2][1]
        end
      end
    end
  end
end
