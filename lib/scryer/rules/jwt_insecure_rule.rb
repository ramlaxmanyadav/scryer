module Scryer
  module Rules
    # Flags insecure usage of the `jwt` gem's `JWT.decode`/`JWT.encode`:
    #   - `JWT.decode(token, secret, false, ...)` — the third positional arg
    #     literal `false` disables signature verification entirely, so any
    #     caller can forge a token that decodes successfully.
    #   - `algorithm: 'none'` / `'alg' => 'none'` — the "none" algorithm
    #     means the token isn't signed at all.
    #   - A plain string literal passed directly as the secret/key argument
    #     — distinct from HardcodedSecretRule, which only matches
    #     `x = "literal"` assignment targets, not a literal inline in a call
    #     argument.
    class JwtInsecureRule < Rule
      self.rule_id = "jwt_insecure_usage"
      self.category = "security"
      self.default_severity = "critical"
      self.title = "Insecure JWT.decode/JWT.encode usage"
      self.cwe = "CWE-347"
      self.owasp_category = "A02:2021-Cryptographic Failures"
      self.confidence = "high"

      PLACEHOLDER_VALUES = /\A(x+|0+|change-?me|your[_-]?(secret|key)|placeholder|example|dummy|fake|test|redacted|\*+)\z/i.freeze

      def scan
        findings = []

        Ast.each_node(sexp) do |node|
          next unless Ast.tagged?(node, :method_add_arg, :command, :command_call)

          inner = Ast.tagged?(node, :method_add_arg) ? node[1] : node
          receiver_and_name = Ast.call_name(inner)
          next unless receiver_and_name

          receiver, method_name = receiver_and_name
          next unless const_receiver_name(receiver) == "JWT" && %w[decode encode].include?(method_name)

          args = Ast.call_arguments(node)
          line = Ast.line_of(node)

          findings << verify_bypass_finding(line) if method_name == "decode" && Ast.false_literal?(args[2])
          findings << algorithm_none_finding(method_name, line) if algorithm_none?(node)
          findings.concat(inline_secret_finding(method_name, args, line))
        end

        findings
      end

      private

      def verify_bypass_finding(line)
        finding(
          line: line,
          message: "`JWT.decode` is called with `false` for `verify` — signature verification is " \
                    "disabled entirely, so any caller can hand this code a forged token with " \
                    "arbitrary claims and it will be accepted as valid.",
          suggested_fix: "Pass `true` for `verify` and supply the correct `algorithm:` option, e.g. " \
                          "`JWT.decode(token, secret, true, algorithm: 'HS256')`."
        )
      end

      def algorithm_none?(node)
        Ast.each_node(node).any? do |n|
          next false unless Ast.tagged?(n, :assoc_new)

          key = assoc_key_text(n[1])
          next false unless key && %w[algorithm alg].include?(key.downcase)

          value = assoc_value_text(n[2])
          value&.downcase == "none"
        end
      end

      def algorithm_none_finding(method_name, line)
        finding(
          line: line,
          message: "`JWT.#{method_name}` is called with `algorithm: 'none'` — the \"none\" " \
                    "algorithm means the token carries no signature at all, so its claims can be " \
                    "freely modified/forged by anyone.",
          suggested_fix: "Use a real signing algorithm (e.g. `algorithm: 'HS256'` or `'RS256'`) and " \
                          "never accept `'none'` from user/client input when choosing it."
        )
      end

      def inline_secret_finding(method_name, args, line)
        secret_arg = args[1]
        secret = secret_arg && Ast.plain_string_value(secret_arg)
        return [] unless secret && !secret.strip.empty? && !PLACEHOLDER_VALUES.match?(secret.strip)

        [
          finding(
            line: line,
            message: "`JWT.#{method_name}` is called with a literal string as the signing " \
                      "secret/key — anyone with read access to this source (including git " \
                      "history) can forge or verify tokens with it.",
            suggested_fix: "Move the secret out of source (`ENV.fetch(\"JWT_SECRET\")` or Rails " \
                            "encrypted credentials) and rotate this value since it's likely " \
                            "already exposed in git history."
          )
        ]
      end

      def assoc_key_text(key_node)
        return key_node[1].to_s.delete_suffix(":") if key_node.is_a?(Array) && key_node[0] == :@label

        Ast.plain_string_value(key_node) || Ast.literal_text(key_node)
      end

      def assoc_value_text(value_node)
        Ast.plain_string_value(value_node) || Ast.literal_text(value_node)
      end

      def const_receiver_name(node)
        if Ast.tagged?(node, :var_ref) && node[1].is_a?(Array) && node[1][0] == :@const
          node[1][1]
        elsif Ast.tagged?(node, :const_path_ref)
          left = const_receiver_name(node[1])
          right = node[2].is_a?(Array) && node[2][0] == :@const ? node[2][1] : nil
          [left, right].compact.join("::")
        end
      end
    end
  end
end
