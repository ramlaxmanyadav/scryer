module Scryer
  module Rules
    # Flags `config.secret_key_base = "literal"` (or
    # `Rails.application.config.secret_key_base = "literal"`) — a plain
    # string literal assigned to `secret_key_base` via a `.field=` target.
    #
    # HardcodedSecretRule doesn't catch this shape: its `target_name` walks
    # the assignment target depth-first and returns the *first* identifier
    # it finds, which for a `.field=` target with a receiver is the
    # receiver's own name (`config`) rather than the attribute being
    # assigned (`secret_key_base`) — so `config.secret_key_base = "..."`
    # never matches its NAME_PATTERN, even though the value is exactly the
    # kind of credential that rule exists to catch. Bare assignment
    # (`secret_key_base = "..."` with no receiver) IS already caught by
    # HardcodedSecretRule, since there the identifier IS the target name —
    # this rule only covers the receiver'd shape it misses.
    class HardcodedSecretKeyBaseRule < Rule
      self.rule_id = "hardcoded_secret_key_base"
      self.category = "security"
      self.default_severity = "critical"
      self.title = "Hardcoded secret_key_base"
      self.cwe = "CWE-798"
      self.owasp_category = "A02:2021-Cryptographic Failures"
      self.confidence = "high"

      PLACEHOLDER_VALUES = /\A(x+|0+|change-?me|placeholder|example|dummy|fake|test|redacted|\*+)\z/i.freeze

      def scan
        findings = []

        Ast.each_node(sexp) do |node|
          next unless Ast.tagged?(node, :assign)

          target = node[1]
          next unless Ast.tagged?(target, :field)
          next unless Ast.ident_text(target[3]) == "secret_key_base"

          value = Ast.plain_string_value(node[2])
          next unless value && !value.strip.empty? && !PLACEHOLDER_VALUES.match?(value.strip)

          line = Ast.line_of(node)
          findings << finding(
            line: line,
            message: "`secret_key_base` is assigned a literal string — this key signs/encrypts " \
                      "Rails sessions and other secrets; anyone with read access to this source " \
                      "(including git history) can forge session cookies and other signed data.",
            suggested_fix: "Use `Rails.application.credentials.secret_key_base` (the Rails default, " \
                            "set via `bin/rails credentials:edit`) or `ENV.fetch(\"SECRET_KEY_BASE\")` " \
                            "instead, and rotate this key since it's likely already exposed in git " \
                            "history."
          )
        end

        findings
      end
    end
  end
end
