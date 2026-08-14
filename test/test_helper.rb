require "minitest/autorun"
require "ripper"
require_relative "../lib/scryer"

module ScryerTestHelper
  # Instantiates `rule_class` against `source` (parsed fresh with Ripper) and
  # returns the Array of Scryer::Finding its #scan produces. Raises loudly if
  # `source` doesn't parse — a fixture with a Ruby syntax error is a bug in
  # the fixture, not something a rule should silently no-op on.
  def scan_with(rule_class, file:, source:)
    sexp = Ripper.sexp(source)
    raise "Fixture source failed to parse (syntax error) for #{rule_class}:\n#{source}" if sexp.nil?

    rule_class.new(file: file, source: source, sexp: sexp).scan
  end
end
