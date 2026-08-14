module Scryer
  module Rules
    # Flags plain string literals assigned to a constant/variable/hash-key
    # whose name looks secret-ish (API_KEY, secret, token, password, ...),
    # OR that match a known cloud-provider key format (AWS access key,
    # generic high-entropy-looking tokens), regardless of variable name.
    class HardcodedSecretRule < Rule
      self.rule_id = "hardcoded_secret"
      self.category = "security"
      self.default_severity = "critical"
      self.title = "Hardcoded credential or API key"
      self.cwe = "CWE-798"
      self.owasp_category = "A07:2021-Identification and Authentication Failures"
      self.confidence = "medium"

      NAME_PATTERN = /(api[_-]?key|secret|token|password|passwd|access[_-]?key|private[_-]?key|auth)/i.freeze

      # High-precision patterns: distinctive enough prefixes/formats that a
      # match alone (regardless of variable name) is worth flagging.
      KNOWN_KEY_PATTERNS = {
        "AWS Access Key ID" => /\bAKIA[0-9A-Z]{16}\b/,
        "Stripe API Key" => /\bsk_(live|test)_[0-9a-zA-Z]{16,}\b/,
        "GitHub Token" => /\bgh[pousr]_[0-9a-zA-Z]{20,}\b/,
        "Slack Token" => /\bxox[baprs]-[0-9a-zA-Z-]{10,}\b/,
        "Private Key block" => /-----BEGIN (RSA |EC )?PRIVATE KEY-----/
      }.freeze

      # Low-precision heuristics: only meaningful when ALSO paired with a
      # suspicious variable/constant name (a bare 40-char base64-ish string
      # is just as likely to be a git SHA, a hash, or a test fixture id).
      WEAK_KEY_PATTERNS = {
        "AWS Secret Access Key (heuristic)" => /\A[A-Za-z0-9\/+=]{40}\z/
      }.freeze

      # Placeholders/examples that should never be flagged even if they match
      # a pattern above or a suspicious name — avoids noisy false positives on
      # obviously-fake sample values.
      PLACEHOLDER_VALUES = /\A(x+|0+|change-?me|your[_-]?(api[_-]?)?key|placeholder|example|dummy|fake|test|redacted|\*+)\z/i.freeze

      def scan
        findings = []

        Ast.each_node(sexp) do |node|
          next unless Ast.tagged?(node, :assign)

          target = node[1]
          value_node = node[2]
          value = Ast.plain_string_value(value_node)
          next unless value
          next if value.strip.empty? || value.length < 6
          next if PLACEHOLDER_VALUES.match?(value.strip)

          name = target_name(target)
          matched_known = KNOWN_KEY_PATTERNS.find { |_label, pattern| pattern.match?(value) }
          matched_weak = WEAK_KEY_PATTERNS.find { |_label, pattern| pattern.match?(value.strip) }
          suspicious_name = name && NAME_PATTERN.match?(name)

          next unless matched_known || suspicious_name || (matched_weak && suspicious_name)

          line = Ast.line_of(node)
          reason =
            if matched_known
              "matches the format of a #{matched_known[0]}"
            elsif matched_weak && suspicious_name
              "matches the format of a #{matched_weak[0]} and is assigned to `#{name}`"
            else
              "is assigned to `#{name}`, a name that suggests a credential"
            end
          findings << finding(
            line: line,
            message: "A literal string #{reason} — secrets committed to source control end up " \
                      "in git history permanently, even if removed later.",
            suggested_fix: "Move this value out of the codebase: use `ENV.fetch(\"#{env_name(name)}\")` " \
                            "or Rails encrypted credentials (`Rails.application.credentials.dig(...)`), " \
                            "set the real value via your deploy environment / secrets manager, and " \
                            "rotate this specific key since it's likely already exposed in git history."
          )
        end

        findings
      end

      private

      def target_name(node)
        Ast.each_node(node).each do |n|
          next unless n.is_a?(Array) && n[0].is_a?(Symbol)

          return n[1] if %i[@const @ident @ivar @gvar @label].include?(n[0]) && n[1].is_a?(String)
        end
        nil
      end

      def env_name(name)
        (name || "SECRET").to_s.gsub(/[^a-zA-Z0-9]+/, "_").upcase.sub(/\A_+|_+\z/, "")
      end
    end
  end
end
