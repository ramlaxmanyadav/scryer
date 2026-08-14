module Scryer
  # Base class for a single detection rule. Subclasses implement `#scan` and
  # return an Array of Finding. Every rule gets the parsed sexp tree (so it
  # doesn't have to re-parse), the raw source (for snippet extraction), and
  # the relative file path (for reporting).
  class Rule
    class << self
      attr_accessor :rule_id, :category, :default_severity, :title, :cwe, :owasp_category

      # "high"/"medium"/"low" — Scryer's own best-effort estimate of how
      # often *this specific rule's* pattern-match actually reflects a real
      # issue, independent of `severity` (how bad it is *if* real). A rule
      # can be both high-severity and low-confidence at once (idor is the
      # clearest example: a real IDOR is serious, but this rule's heuristic
      # — no visible authorization call anywhere in the controller class —
      # is the least precise in the gem). Defaults to "medium" so every
      # rule doesn't have to set it explicitly; only rules with a clearly
      # different precision (idor's documented false-positive risk, or a
      # narrow literal-match rule with very little room for ambiguity) set
      # this themselves. Not derived from anything measured at runtime —
      # this is a static per-rule estimate, same as `default_severity`.
      def confidence
        @confidence || "medium"
      end
      attr_writer :confidence

      def inherited(subclass)
        super
        Scryer::RuleSet.register(subclass)
      end
    end

    def initialize(file:, source:, sexp:)
      @file = file
      @source = source
      @sexp = sexp
    end

    attr_reader :file, :source, :sexp

    def scan
      raise NotImplementedError, "#{self.class} must implement #scan"
    end

    private

    def finding(line:, message:, suggested_fix:, severity: self.class.default_severity, confidence: self.class.confidence)
      Finding.new(
        rule_id: self.class.rule_id,
        category: self.class.category,
        severity: severity,
        confidence: confidence,
        cwe: self.class.cwe,
        owasp_category: self.class.owasp_category,
        file: file,
        line: line,
        code_snippet: Ast.source_line(source, line),
        message: message,
        suggested_fix: suggested_fix
      )
    end
  end
end
