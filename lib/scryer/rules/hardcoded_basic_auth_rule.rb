module Scryer
  module Rules
    # Flags `http_basic_authenticate_with` calls whose `password:` (or
    # `name:`) keyword argument is a plain string literal — a shape
    # `HardcodedSecretRule` doesn't cover (that rule only looks at
    # `x = "literal"` assignment targets, not keyword-argument values in a
    # method call).
    class HardcodedBasicAuthRule < Rule
      self.rule_id = "hardcoded_basic_auth"
      self.category = "security"
      self.default_severity = "critical"
      self.title = "Hardcoded HTTP Basic Auth credential"

      PLACEHOLDER_VALUES = /\A(x+|0+|change-?me|your[_-]?password|placeholder|example|dummy|fake|test|redacted|\*+)\z/i.freeze

      def scan
        findings = []

        Ast.each_node(sexp) do |node|
          next unless Ast.tagged?(node, :method_add_arg, :command, :command_call)

          inner = Ast.tagged?(node, :method_add_arg) ? node[1] : node
          name_pair = Ast.call_name(inner)
          next unless name_pair && name_pair[1] == "http_basic_authenticate_with"

          args = Ast.call_arguments(node)
          password_value = Ast.plain_string_value(Ast.keyword_arg(args, "password"))
          next unless password_value && !password_value.strip.empty? && !PLACEHOLDER_VALUES.match?(password_value.strip)

          line = Ast.line_of(node)
          findings << finding(
            line: line,
            message: "`http_basic_authenticate_with` is called with a literal `password:` — " \
                      "anyone with read access to this source (including git history) has the " \
                      "credential, and it can't be rotated without a code change and deploy.",
            suggested_fix: "Move the credential out of source: " \
                            "`http_basic_authenticate_with name: ENV.fetch(\"BASIC_AUTH_USER\"), " \
                            "password: ENV.fetch(\"BASIC_AUTH_PASSWORD\")` (or Rails encrypted " \
                            "credentials), and rotate this password since it's likely already " \
                            "exposed in git history."
          )
        end

        findings
      end
    end
  end
end
