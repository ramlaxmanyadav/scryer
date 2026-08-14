module Scryer
  module Rules
    # Flags a controller's `index` action that queries a model directly
    # (`Model.all`/`Model.where(...)`) instead of through Pundit's
    # `policy_scope`, in a controller that clearly *uses* Pundit elsewhere
    # (an `authorize` call appears somewhere in the class) — the well-known
    # Pundit gotcha where a team remembers `authorize` on show/update/destroy
    # (each of which checks one record) but forgets that `index` needs
    # `policy_scope` instead, since there's no single record for `authorize`
    # to check. Scoped to controllers that already show Pundit usage
    # specifically so this doesn't fire on apps that don't use Pundit at all
    # (no `authorize` anywhere) or that scope their index some other way
    # entirely (a `current_user.posts.all` association instead of a bare
    # `Post.all` is already scoped, and isn't flagged — see
    # `references_unscoped_query?`).
    #
    # Same looseness as MassAssignmentRule#has_permit_call? and
    # PathTraversalRule#sanitized_via_basename?: checks whether
    # `policy_scope` appears *anywhere* in the `index` method body, not that
    # it specifically wraps the `Model.all`/`.where` call — good enough to
    # catch the common case (a bare unscoped query with no policy_scope call
    # at all in sight) without a much harder "does this specific call sit
    # inside that specific block" analysis.
    class MissingPolicyScopeRule < Rule
      self.rule_id = "missing_policy_scope"
      self.category = "security"
      self.default_severity = "warning"
      self.title = "index action queries a model without policy_scope"
      self.cwe = "CWE-862"
      self.owasp_category = "A01:2021-Broken Access Control"
      self.confidence = "medium"

      UNSCOPED_METHODS = %w[all where].freeze
      # Same list IdorRule/MassAssignmentRule use for the same reason —
      # stdlib/gem constants with their own `.all`/`.where`-shaped methods
      # that have nothing to do with an ActiveRecord model query.
      NON_MODEL_RECEIVERS = %w[
        Struct OpenStruct Data Class Module BCrypt OpenSSL Net URI Digest
        JSON YAML Marshal String Array Hash Integer Float Symbol Comparable
        Enumerable File Dir
      ].freeze

      def scan
        findings = []

        Ast.each_node(sexp) do |node|
          next unless Ast.tagged?(node, :class)

          class_name = Ast.class_name(node[1])
          next unless class_name.to_s.end_with?("Controller")

          body = node[3]
          next unless each_call_names(body).include?("authorize") # uses Pundit at all

          each_index_def(body).each do |def_node|
            index_body = def_node[3]
            next if each_call_names(index_body).include?("policy_scope")

            query_node = find_unscoped_query(index_body)
            next unless query_node

            findings << finding(
              line: Ast.line_of(query_node),
              message: "`#{class_name}#index` queries a model directly (`#{describe_call(query_node)}`) " \
                        "instead of through `policy_scope` — this controller uses Pundit's `authorize` " \
                        "elsewhere, but `index` needs `policy_scope` instead (there's no single record " \
                        "for `authorize` to check), so every record is visible here regardless of who's " \
                        "allowed to see what.",
              suggested_fix: "Wrap the query in `policy_scope`, e.g. `policy_scope(#{receiver_name(query_node)}).all` " \
                              "instead of `#{describe_call(query_node)}`, and define the corresponding " \
                              "Scope class in this model's policy."
            )
          end
        end

        findings
      end

      private

      def each_call_names(node)
        Ast.each_node(node).flat_map do |n|
          next [] unless Ast.tagged?(n, :method_add_arg, :command, :command_call, :fcall, :vcall)

          inner = Ast.tagged?(n, :method_add_arg) ? n[1] : n
          [Ast.call_name(inner)&.last].compact
        end
      end

      def each_index_def(body)
        Ast.each_node(body).select { |n| Ast.tagged?(n, :def) && Ast.ident_text(n[1]) == "index" }
      end

      def find_unscoped_query(node)
        Ast.each_node(node).find do |n|
          next false unless Ast.tagged?(n, :method_add_arg, :call, :command, :command_call)

          inner = Ast.tagged?(n, :method_add_arg) ? n[1] : n
          receiver_and_name = Ast.call_name(inner)
          next false unless receiver_and_name

          receiver, method_name = receiver_and_name
          UNSCOPED_METHODS.include?(method_name) && likely_model_receiver?(receiver)
        end
      end

      def likely_model_receiver?(receiver)
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

      def receiver_name(query_node)
        inner = Ast.tagged?(query_node, :method_add_arg) ? query_node[1] : query_node
        const_receiver_name(Ast.call_name(inner)&.first) || "Model"
      end

      def describe_call(query_node)
        inner = Ast.tagged?(query_node, :method_add_arg) ? query_node[1] : query_node
        receiver, method_name = Ast.call_name(inner)
        "#{const_receiver_name(receiver)}.#{method_name}"
      end
    end
  end
end
