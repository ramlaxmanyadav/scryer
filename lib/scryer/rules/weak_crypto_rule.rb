module Scryer
  module Rules
    # Flags `Digest::MD5`/`Digest::SHA1` used in a context that looks like
    # password/credential hashing (method or nearby variable name contains
    # "password"/"passwd") — both are cryptographically broken for that use
    # case; a fast general-purpose hash lets an attacker who steals the DB
    # brute-force passwords far faster than a proper password hash
    # (bcrypt/scrypt/argon2, which are deliberately slow).
    class WeakCryptoRule < Rule
      self.rule_id = "weak_crypto"
      self.category = "security"
      self.default_severity = "warning"
      self.title = "Weak hash algorithm used for password/credential hashing"

      WEAK_DIGESTS = %w[MD5 SHA1].freeze
      PASSWORD_HINT = /password|passwd|credential/i.freeze

      def scan
        findings = []

        Ast.each_node(sexp) do |node|
          next unless Ast.tagged?(node, :top_const_ref, :const_path_ref, :var_ref)

          digest_name = digest_algorithm_name(node)
          next unless digest_name

          # Only flag when something nearby (same statement/line) mentions
          # password-ish naming — Digest::MD5/SHA1 have plenty of legitimate
          # non-credential uses (cache keys, ETags, checksums) that shouldn't
          # be flagged as a crypto weakness.
          line = Ast.line_of(node)
          context_line = Ast.source_line(source, line).to_s
          next unless PASSWORD_HINT.match?(context_line)

          findings << finding(
            line: line,
            message: "`Digest::#{digest_name}` is used near what looks like password/credential " \
                      "handling — #{digest_name} is fast and unsalted by default, making stolen " \
                      "hashes practical to brute-force.",
            suggested_fix: "Use `bcrypt` via Rails' `has_secure_password` for password storage " \
                            "instead of a general-purpose digest — it's deliberately slow and " \
                            "handles salting automatically. Reserve Digest::#{digest_name} for " \
                            "non-credential uses (cache keys, checksums)."
          )
        end

        findings
      end

      private

      # Matches `Digest::MD5` / `Digest::SHA1` referenced as a constant path.
      def digest_algorithm_name(node)
        text = Ast.each_node(node)
                         .filter_map { |n| n.is_a?(Array) && n[0] == :@const ? n[1] : nil }
                         .join("::")

        WEAK_DIGESTS.find { |name| text == "Digest::#{name}" || text == name && sexp_mentions_digest?(node) }
      end

      def sexp_mentions_digest?(node)
        Ast.each_node(node).any? { |n| n.is_a?(Array) && n[0] == :@const && n[1] == "Digest" }
      end
    end
  end
end
