module Scryer
  module Rules
    # Flags Ruby files with no `# frozen_string_literal: true` magic comment
    # — the one deliberate, narrow style check Scryer makes (see the
    # README's Scryer-vs-RuboCop comparison: everything else in
    # style/lint conventions is intentionally left to RuboCop). Checked on
    # raw source rather than the parsed sexp — a magic comment is lexical,
    # not part of the AST — so this only needs the file's leading lines,
    # not Ripper.sexp.
    class FrozenStringLiteralRule < Rule
      self.rule_id = "frozen_string_literal"
      self.category = "style"
      self.default_severity = "info"
      self.title = "Missing `frozen_string_literal` magic comment"
      self.confidence = "high"

      MAGIC_COMMENT = /\A#\s*frozen_string_literal:\s*(true|false)\s*\z/i.freeze

      def scan
        return [] if source.strip.empty?
        return [] if leading_comment_lines.any? { |line| MAGIC_COMMENT.match?(line.strip) }

        [
          finding(
            line: 1,
            message: "This file has no `# frozen_string_literal: true` magic comment — every " \
                      "string literal allocates a new String object at runtime instead of reusing " \
                      "a single frozen one.",
            suggested_fix: "Add `# frozen_string_literal: true` as the first line of the file " \
                            "(after a shebang line, if any) — a cheap, safe default in modern " \
                            "Ruby. If a specific literal needs to stay mutable, call `.dup` on it " \
                            "explicitly at that call site."
          )
        ]
      end

      private

      # The lines Ruby itself considers when looking for a magic comment:
      # starting from the top of the file, skip a shebang line, then take
      # every line up to (not including) the first line that isn't blank or
      # a comment.
      def leading_comment_lines
        lines = source.each_line.to_a
        lines.shift if lines.first&.start_with?("#!")

        lines.take_while { |line| line.strip.empty? || line.lstrip.start_with?("#") }
      end
    end
  end
end
