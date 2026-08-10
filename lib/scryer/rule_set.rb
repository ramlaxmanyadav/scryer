module Scryer
  # Registry of every Rule subclass (rules self-register via Rule.inherited).
  # Scanner uses .all to run every registered rule against each parsed file.
  module RuleSet
    class << self
      def register(rule_class)
        registry << rule_class
      end

      def registry
        @registry ||= []
      end

      def all
        registry
      end
    end
  end
end
