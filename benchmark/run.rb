#!/usr/bin/env ruby
# frozen_string_literal: true

require "ripper"
$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))
require "scryer"
require_relative "corpus"

# Runs every sample in benchmark/corpus.rb through the same Rule#scan path a
# real scan uses (Ripper.sexp + Rule.new(...).scan — no simulation, no mock),
# and reports precision/recall/F1 per rule plus an aggregate across the
# corpus. See benchmark/README.md for what these numbers do and don't mean
# before quoting one.
module Scryer
  module Benchmark
    Tally = Struct.new(:rule_id, :tp, :fn, :fp, :tn) do
      def precision
        (tp + fp).zero? ? nil : tp.to_f / (tp + fp)
      end

      def recall
        (tp + fn).zero? ? nil : tp.to_f / (tp + fn)
      end

      def f1
        p, r = precision, recall
        return nil if p.nil? || r.nil? || (p + r).zero?

        2 * p * r / (p + r)
      end

      def total
        tp + fn + fp + tn
      end
    end

    module_function

    def fires?(rule_class, sample)
      sexp = Ripper.sexp(sample[:source])
      raise "corpus sample failed to parse (syntax error) for #{rule_class}: #{sample[:source]}" if sexp.nil?

      findings = rule_class.new(file: sample[:file], source: sample[:source], sexp: sexp).scan
      findings.any? { |f| f.rule_id == rule_class.rule_id }
    end

    def run
      CORPUS.map do |rule_id, spec|
        vulnerable = spec[:vulnerable] || []
        safe = spec[:safe] || []

        tp = vulnerable.count { |s| fires?(spec[:rule_class], s) }
        fn = vulnerable.size - tp
        fp = safe.count { |s| fires?(spec[:rule_class], s) }
        tn = safe.size - fp

        Tally.new(rule_id, tp, fn, fp, tn)
      end
    end

    def aggregate(tallies)
      Tally.new("TOTAL", tallies.sum(&:tp), tallies.sum(&:fn), tallies.sum(&:fp), tallies.sum(&:tn))
    end

    def format_pct(value)
      value.nil? ? "n/a" : "#{(value * 100).round(1)}%"
    end

    def print_console(tallies)
      registered = Scryer::RuleSet.all.map(&:rule_id).sort
      covered = tallies.map(&:rule_id).sort
      missing = registered - covered
      puts "Scryer accuracy benchmark — #{tallies.size}/#{registered.size} rules covered"
      puts "(#{missing.size} rule(s) not yet in the corpus: #{missing.join(', ')})" unless missing.empty?
      puts "-" * 100
      printf("%-45s %5s %5s %5s %5s %10s %10s %8s\n", "rule_id", "TP", "FN", "FP", "TN", "precision", "recall", "f1")
      tallies.sort_by(&:rule_id).each do |t|
        printf("%-45s %5d %5d %5d %5d %10s %10s %8s\n",
               t.rule_id, t.tp, t.fn, t.fp, t.tn, format_pct(t.precision), format_pct(t.recall), format_pct(t.f1))
      end
      puts "-" * 100
      total = aggregate(tallies)
      printf("%-45s %5d %5d %5d %5d %10s %10s %8s\n",
             total.rule_id, total.tp, total.fn, total.fp, total.tn,
             format_pct(total.precision), format_pct(total.recall), format_pct(total.f1))
      puts "\n#{tallies.sum(&:total)} labeled samples across #{tallies.size} rules. See benchmark/README.md " \
           "for the honesty caveat on what these numbers do and don't mean."
    end

    def print_markdown(tallies)
      puts "| Rule | TP | FN | FP | TN | Precision | Recall | F1 |"
      puts "|------|----|----|----|----|-----------|--------|----| "
      tallies.sort_by(&:rule_id).each do |t|
        puts "| `#{t.rule_id}` | #{t.tp} | #{t.fn} | #{t.fp} | #{t.tn} | #{format_pct(t.precision)} | " \
             "#{format_pct(t.recall)} | #{format_pct(t.f1)} |"
      end
      total = aggregate(tallies)
      puts "| **TOTAL** | #{total.tp} | #{total.fn} | #{total.fp} | #{total.tn} | " \
           "**#{format_pct(total.precision)}** | **#{format_pct(total.recall)}** | **#{format_pct(total.f1)}** |"
    end
  end
end

if __FILE__ == $PROGRAM_NAME
  tallies = Scryer::Benchmark.run
  if ARGV.include?("--md")
    Scryer::Benchmark.print_markdown(tallies)
  else
    Scryer::Benchmark.print_console(tallies)
  end
end
