module Scryer
  # Base class for a single detection rule. Subclasses implement `#scan` and
  # return an Array of Finding. Every rule gets the parsed sexp tree (so it
  # doesn't have to re-parse), the raw source (for snippet extraction), and
  # the relative file path (for reporting).
  class Rule
    class << self
      attr_accessor :rule_id, :category, :default_severity, :title

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

    def finding(line:, message:, suggested_fix:, severity: self.class.default_severity)
      Finding.new(
        rule_id: self.class.rule_id,
        category: self.class.category,
        severity: severity,
        file: file,
        line: line,
        code_snippet: Ast.source_line(source, line),
        message: message,
        suggested_fix: suggested_fix
      )
    end
  end
end
