# Opt-in RSpec integration — require this file yourself (e.g. `require
# "scryer/rspec"` in spec_helper.rb) rather than it loading automatically
# with the gem, since RSpec itself is never a Scryer runtime dependency (see
# scryer.gemspec's zero-runtime-dependency design) and this file references
# RSpec::Matchers, which only exists once RSpec has already been loaded by
# the host app. Requiring "scryer" alone never pulls this in.
#
# Turns "did this app's own security scan stay clean" into a normal RSpec
# expectation, so a regression (a new critical finding, or a specific
# previously-fixed rule firing again) fails the test suite the same way any
# other regression would, instead of only showing up the next time someone
# remembers to run `scryer` by hand or a separate CI step notices it.
#
#   RSpec.describe "security" do
#     it "has no critical findings" do
#       expect(Scryer.scan(root: Rails.root.to_s)).to have_no_critical_findings
#     end
#
#     it "never reintroduces the mass-assignment bug fixed in PR #123" do
#       expect(Scryer.scan(root: Rails.root.to_s)).to have_no_findings_for("mass_assignment")
#     end
#   end
#
# Both matchers work against a Scryer::Scanner::Result (what Scryer.scan/
# Scanner#call returns) — style/performance findings are deliberately
# excluded from have_no_critical_findings (only security findings carry
# real security risk; a slow app isn't a "critical" security finding), but
# have_no_findings_for checks all three categories, since a rule regressing
# is worth catching regardless of which category it's filed under.
require "rspec/expectations"

RSpec::Matchers.define :have_no_critical_findings do
  match do |result|
    @criticals = result.security_findings.select { |f| f.severity == "critical" }
    @criticals.empty?
  end

  failure_message do
    lines = @criticals.map { |f| "  - #{f.rule_id} at #{f.file}:#{f.line} — #{f.message}" }
    "expected no critical security findings, but got #{@criticals.size}:\n#{lines.join("\n")}"
  end
end

RSpec::Matchers.define :have_no_findings_for do |rule_id|
  match do |result|
    @matches = (result.security_findings + result.performance_findings + result.style_findings)
               .select { |f| f.rule_id == rule_id.to_s }
    @matches.empty?
  end

  failure_message do
    lines = @matches.map { |f| "  - #{f.file}:#{f.line} — #{f.message}" }
    "expected no findings for rule #{rule_id.inspect}, but got #{@matches.size}:\n#{lines.join("\n")}"
  end
end
