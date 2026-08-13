module Scryer
  module Rules
    # Flags the well-known Rack::Cors antipattern: a wildcard origin
    # (`origins '*'`) combined with `credentials: true` on a `resource` call.
    # Per the CORS spec, browsers reject this combination in practice, but
    # it's still the standard misconfiguration flagged in security reviews —
    # either half alone (wildcard origin with no credentials, or credentials
    # with a real origin allowlist) is fine.
    #
    # Scoped per `allow do ... end` block (Rack::Cors' own grouping
    # construct — each `allow` block gets its own `origins`/`resource`
    # pairing), not file-wide: a common, legitimate pattern is a public,
    # unauthenticated API in one `allow` block (`origins '*'`, no
    # credentials) and a separate authenticated partner API in another
    # `allow` block in the same initializer (a real origin allowlist +
    # `credentials: true`) — neither block alone is a misconfiguration, but
    # an earlier file-wide "does '*' appear ANYWHERE AND does credentials:
    # true appear ANYWHERE" check would flag the second block just because
    # the first one happens to use a wildcard. Requiring both signals to
    # come from the same `allow` block's own subtree fixes that without
    # losing detection of the real antipattern (both signals still just
    # need to appear somewhere *within* one block, not literally on the same
    # `resource` call, since `origins` and `resource` are usually sibling
    # statements in the same block rather than one call).
    class CorsMisconfigurationRule < Rule
      self.rule_id = "cors_misconfiguration"
      self.category = "security"
      self.default_severity = "critical"
      self.title = "CORS wildcard origin combined with credentials"

      def scan
        findings = []

        allow_blocks(sexp).each do |block|
          next unless wildcard_origin_anywhere?(block)

          each_credentialed_resource(block).each do |node|
            findings << finding(
              line: Ast.line_of(node),
              message: "This `allow` block sets a wildcard origin (`origins '*'`) and this " \
                        "`resource` call sets `credentials: true` — browsers won't honor that " \
                        "combination for actual credentialed requests, and Rack::Cors handling it " \
                        "inconsistently is the standard CORS misconfiguration flagged in reviews. " \
                        "Either restrict origins to a real allowlist, or drop `credentials: true`.",
              suggested_fix: "Replace the wildcard with an explicit origin allowlist wherever " \
                              "`credentials: true` is set: `origins 'https://app.example.com'` " \
                              "instead of `origins '*'` — a wildcard origin should only be paired " \
                              "with `credentials: false` (the default)."
            )
          end
        end

        findings
      end

      private

      # Every `allow do ... end` block in the file — Ripper parses it as a
      # `method_add_block` wrapping an `fcall`/`vcall` named "allow" plus its
      # `do_block` body. Rack::Cors configs are always structured this way
      # (`Rack::Cors do allow do ... end end`), so scoping to these blocks
      # rather than falling back to file-wide when none are found doesn't
      # lose real detections in practice.
      def allow_blocks(node)
        Ast.each_node(node).select do |n|
          next false unless Ast.tagged?(n, :method_add_block)

          call_node = n[1]
          inner = Ast.tagged?(call_node, :method_add_arg) ? call_node[1] : call_node
          Ast.call_name(inner)&.last == "allow"
        end
      end

      def wildcard_origin_anywhere?(node)
        Ast.each_node(node).any? do |n|
          next false unless Ast.tagged?(n, :method_add_arg, :command, :command_call)

          inner = Ast.tagged?(n, :method_add_arg) ? n[1] : n
          next false unless Ast.call_name(inner)&.last == "origins"

          Ast.call_arguments(n).any? { |a| Ast.plain_string_value(a) == "*" }
        end
      end

      def each_credentialed_resource(node)
        Ast.each_node(node).select do |n|
          next false unless Ast.tagged?(n, :method_add_arg, :command, :command_call)

          inner = Ast.tagged?(n, :method_add_arg) ? n[1] : n
          next false unless Ast.call_name(inner)&.last == "resource"

          Ast.true_literal?(Ast.keyword_arg(Ast.call_arguments(n), "credentials"))
        end
      end
    end
  end
end
