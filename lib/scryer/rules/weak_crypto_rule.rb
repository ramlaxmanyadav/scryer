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
      self.cwe = "CWE-327"
      self.owasp_category = "A02:2021-Cryptographic Failures"
      self.confidence = "medium"

      WEAK_DIGESTS = %w[MD5 SHA1].freeze

      # `(?!less)` after "password" excludes "passwordless" (and
      # "passwordlessly") specifically — a real identifier that means the
      # *opposite* of what this heuristic is looking for (e.g. a magic-link
      # or passwordless-auth token, `Digest::SHA1.hexdigest(passwordless_token)`),
      # not a credential. It doesn't affect any legitimate match: every other
      # "password"-containing identifier this heuristic cares about
      # (`password`, `user_password`, `password_reset_token`, `hashed_password`,
      # ...) is never immediately followed by the literal substring "less".
      PASSWORD_HINT = /password(?!less)|passwd|credential/i.freeze

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
          context_line = strip_trailing_comment(Ast.source_line(source, line).to_s)
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

      # Strips a trailing `# ...` line comment before running PASSWORD_HINT
      # against the raw source line. Without this, a defensive comment that
      # *disclaims* password use (`Digest::SHA1.hexdigest(file_content) #
      # cache key, not a password hash` — a natural thing to write specifically
      # to preempt this exact kind of static-analysis false positive) still
      # contains the substring "password" and would trip the heuristic just
      # as hard as a genuine mention. This does give up the (much rarer) case
      # where a comment is the *only* signal — e.g. an unnamed argument whose
      # only password-ish hint is a comment describing it — but real
      # password-hashing call sites almost always also have a password-ish
      # identifier in the actual code (`password`, `user.password`, ...),
      # which stays visible on the line after stripping the comment.
      #
      # Deliberately simple rather than a full tokenizer: finds the first `#`
      # that isn't the start of a `#{` string interpolation and treats
      # everything from there as comment. This means a literal `#` inside a
      # string argument on the same line (e.g. `hexdigest("score: #1")`) would
      # be mistaken for a comment start too — an accepted limitation of a
      # same-line text heuristic, not a full parse.
      def strip_trailing_comment(line)
        line.sub(/#(?!\{).*\z/, "")
      end

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
