module Scryer
  module Rules
    # Flags a `class X < GraphQL::Schema` (or a class whose superclass
    # constant path text is exactly `GraphQL::Schema`) whose body calls
    # neither `max_depth` nor `max_complexity` anywhere — without at least
    # one of those, a client can send an arbitrarily deep/expensive query
    # and the server will try to resolve all of it, a common
    # denial-of-service vector for GraphQL APIs. Both missing is flagged as
    # a single finding per class (not one per missing directive), the same
    # "did the class do the safe thing at all" pattern as
    # ActiveStorageMissingContentTypeValidationRule/IdorRule.
    #
    # Known precision limits, both around indirection this rule can't (or
    # doesn't try to) resolve, same disclosed-gap spirit as IdorRule:
    #
    #   - A schema that inherits from a shared custom base class (e.g.
    #     `class MySchema < BaseSchema`, where `BaseSchema` is the one that
    #     actually extends `GraphQL::Schema` and calls `max_depth`/
    #     `max_complexity`) is never even examined by this rule — the
    #     superclass-name check only matches a literal `GraphQL::Schema`
    #     superclass, so `MySchema` here isn't checked at all (a
    #     false-negative blind spot, not a false positive: verified via
    #     `Scryer::Scanner` that such a subclass produces no finding either
    #     way).
    #   - Conversely, a class that DOES extend `GraphQL::Schema` directly
    #     but gets its limits from an `include`d module (e.g. `include
    #     QueryLimits`, where the module sets `max_depth`/`max_complexity`
    #     via its own `included do ... end` block in a different file) WILL
    #     be flagged as missing them, even though it isn't — confirmed via
    #     `Scryer::Scanner` against exactly this fixture. Resolving what an
    #     `include`d module does requires following it to its own
    #     definition, potentially in another file entirely — real
    #     cross-file resolution, not a same-file AST tweak — so rather than
    #     risk a broad/wrong exemption (e.g. "any class that calls
    #     `include` at all is exempt" would silence the rule for classes
    #     that include something unrelated and still have no real limit),
    #     this gap is left as-is and disclosed here instead. Treat a
    #     finding on a schema using a shared limits module as worth a
    #     second look, not a confirmed bug.
    class GraphqlMissingQueryLimitsRule < Rule
      self.rule_id = "graphql_missing_query_limits"
      self.category = "security"
      self.default_severity = "warning"
      self.title = "GraphQL schema without query depth/complexity limits"
      self.cwe = "CWE-770"
      self.owasp_category = "A04:2021-Insecure Design"
      self.confidence = "medium"

      LIMIT_METHODS = %w[max_depth max_complexity].freeze

      def scan
        findings = []

        Ast.each_node(sexp) do |node|
          next unless Ast.tagged?(node, :class)

          superclass = superclass_name(node[2])
          next unless superclass == "GraphQL::Schema"

          body = node[3]
          next if each_call_names(body).any? { |name| LIMIT_METHODS.include?(name) }

          class_name = Ast.ident_text(node[1].is_a?(Array) ? node[1][1] : nil)
          line = Ast.line_of(node)
          findings << finding(
            line: line,
            message: "`#{class_name}` extends `GraphQL::Schema` but calls neither `max_depth` nor " \
                      "`max_complexity` — without either limit, a client can send an arbitrarily " \
                      "deep or expensive query and the server will attempt to resolve all of it, a " \
                      "common denial-of-service vector for GraphQL APIs.",
            suggested_fix: "Add at least one limit to the schema, e.g. `max_depth 15` and/or " \
                            "`max_complexity 300` (tune both to what this API's real queries need)."
          )
        end

        findings
      end

      private

      def each_call_names(body)
        Ast.each_node(body).filter_map do |n|
          next unless Ast.tagged?(n, :method_add_arg, :command, :command_call, :fcall, :vcall)

          inner = Ast.tagged?(n, :method_add_arg) ? n[1] : n
          Ast.call_name(inner)&.last
        end
      end

      # Textual name of a (possibly namespaced) constant superclass node —
      # "GraphQL::Schema" for the `[:const_path_ref, ...]` chain a `< X::Y`
      # superclass parses into, or the bare name for an unnamespaced
      # superclass (`[:var_ref, [:@const, ...]]`). nil if there's no
      # superclass (`node[2]` is nil for a plain `class X` with no `< ...`).
      def superclass_name(node)
        if Ast.tagged?(node, :var_ref) && node[1].is_a?(Array) && node[1][0] == :@const
          node[1][1]
        elsif Ast.tagged?(node, :const_path_ref)
          left = superclass_name(node[1])
          right = node[2].is_a?(Array) && node[2][0] == :@const ? node[2][1] : nil
          [left, right].compact.join("::")
        end
      end
    end
  end
end
