# Opt-in Minitest integration — require this file yourself (e.g. `require
# "scryer/minitest"` in test_helper.rb) rather than it loading automatically
# with the gem; same reasoning as lib/scryer/rspec.rb (Minitest is never a
# Scryer runtime dependency, and this file's assertions only make sense once
# the host app's own test framework is already loaded).
#
# Mix Scryer::MinitestAssertions into a Minitest::Test (or
# ActiveSupport::TestCase, which is one) to assert this app's own security
# scan stays clean as part of its normal test suite:
#
#   class SecurityTest < ActiveSupport::TestCase
#     include Scryer::MinitestAssertions
#
#     test "no critical findings" do
#       assert_no_critical_scryer_findings(Scryer.scan(root: Rails.root.to_s))
#     end
#
#     test "the mass-assignment bug fixed in PR #123 doesn't come back" do
#       assert_no_scryer_findings_for(Scryer.scan(root: Rails.root.to_s), "mass_assignment")
#     end
#   end
module Scryer
  module MinitestAssertions
    # Only security findings — style/performance findings aren't a security
    # regression, same scoping as the RSpec have_no_critical_findings matcher.
    def assert_no_critical_scryer_findings(result, msg = nil)
      criticals = result.security_findings.select { |f| f.severity == "critical" }
      default_msg = -> {
        lines = criticals.map { |f| "  - #{f.rule_id} at #{f.file}:#{f.line} — #{f.message}" }
        "expected no critical security findings, but got #{criticals.size}:\n#{lines.join("\n")}"
      }
      assert criticals.empty?, msg || default_msg.call
    end

    # Checks all three categories (security/performance/style) — a rule
    # regressing is worth catching regardless of which category it's filed
    # under, unlike assert_no_critical_scryer_findings above.
    def assert_no_scryer_findings_for(result, rule_id, msg = nil)
      matches = (result.security_findings + result.performance_findings + result.style_findings)
                .select { |f| f.rule_id == rule_id.to_s }
      default_msg = -> {
        lines = matches.map { |f| "  - #{f.file}:#{f.line} — #{f.message}" }
        "expected no findings for rule #{rule_id.inspect}, but got #{matches.size}:\n#{lines.join("\n")}"
      }
      assert matches.empty?, msg || default_msg.call
    end
  end
end
