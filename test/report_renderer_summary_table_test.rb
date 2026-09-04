require_relative "test_helper"

# Scryer::ReportRenderer's Summary table — specifically the Dependency audit
# row and the Total row's arithmetic. Regression test: the Dependency audit
# row used to render "—" for every severity column (no breakdown at all),
# and the Total row's sum excluded dependency findings entirely — so a
# report with only dependency findings showed "0/0/0/0" in this table's
# Total row while the executive summary's severity bars just above it (which
# do count dependency findings) showed nonzero counts. Same numbers, two
# different totals on the same page.
class ReportRendererSummaryTableTest < Minitest::Test
  def dependency_finding(severity:)
    Scryer::DependencyAudit::Finding.new(
      kind: "vulnerable_dependency", gem_name: "nokogiri", installed_version: "1.19.4",
      severity: severity, advisory_id: "GHSA-fake", title: "fake vuln",
      patched_versions: [], message: "fake", suggested_fix: "fake"
    )
  end

  def empty_result
    Scryer::Scanner::Result.new(
      security_findings: [], performance_findings: [], style_findings: [],
      duplicate_groups: [], files_scanned: 1, parse_errors: []
    )
  end

  def test_dependency_audit_row_shows_real_severity_counts_not_a_dash
    html = Scryer::ReportRenderer.new(
      result: empty_result, project_name: "test",
      dependency_findings: [dependency_finding(severity: "warning"), dependency_finding(severity: "info")]
    ).as_html

    summary_table = html[/<table class="summary">.*?<\/table>/m]
    deps_row = summary_table[/<tr><th>Dependency audit<\/th>.*?<\/tr>/m]

    refute_nil deps_row, "expected a Dependency audit row in the Summary table"
    refute_match(/colspan="3">—</, deps_row, "Dependency audit row should show real counts, not a dash placeholder")
    assert_match(/<td>0<\/td><td>1<\/td><td>1<\/td>/, deps_row, "expected 0 critical, 1 warning, 1 info")
  end

  def test_total_row_includes_dependency_findings_in_its_sum
    html = Scryer::ReportRenderer.new(
      result: empty_result, project_name: "test",
      dependency_findings: [dependency_finding(severity: "warning"), dependency_finding(severity: "info")]
    ).as_html

    summary_table = html[/<table class="summary">.*?<\/table>/m]
    total_row = summary_table[/<tr class="total">.*?<\/tr>/m]

    refute_nil total_row, "expected a Total row in the Summary table"
    # Total should be 2 (1 warning + 1 info from the dependency findings
    # above) — previously this row summed only security+performance+style
    # and would have shown 0 here despite 2 real findings existing.
    assert_match(/>2<\/td><\/tr>\z/, total_row, "Total row's final cell should reflect the 2 dependency findings")
  end
end
