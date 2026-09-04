require_relative "test_helper"

# Scryer::ReportRenderer#security_score — no prior test file covered the
# score formula at all before this. Locks in the severity/confidence weights
# (Scryer::ReportRenderer::SCORE_SEVERITY_WEIGHT/SCORE_CONFIDENCE_WEIGHT) so a
# future change to them is a deliberate, visible diff here rather than a
# silent drift in what the score means.
class SecurityScoreTest < Minitest::Test
  def finding(severity:, confidence: "medium", rule_id: "sql_injection", category: "security")
    Scryer::Finding.new(
      rule_id: rule_id, category: category, severity: severity, confidence: confidence,
      cwe: "CWE-89", owasp_category: "A03:2021-Injection", file: "app/models/x.rb", line: 1,
      code_snippet: "x", message: "example", suggested_fix: "example"
    )
  end

  def result_with(findings, performance_findings: [], style_findings: [])
    Scryer::Scanner::Result.new(
      security_findings: findings, performance_findings: performance_findings, style_findings: style_findings,
      duplicate_groups: [], files_scanned: 1, parse_errors: []
    )
  end

  def score_for(findings, dependency_findings: [], performance_findings: [], style_findings: [])
    Scryer::ReportRenderer.new(
      result: result_with(findings, performance_findings: performance_findings, style_findings: style_findings),
      project_name: "test", dependency_findings: dependency_findings
    ).security_score
  end

  def test_a_clean_scan_scores_100_a
    score = score_for([])
    assert_equal 100, score["score"]
    assert_equal "A", score["grade"]
  end

  def test_a_single_high_confidence_critical_finding_visibly_moves_the_score
    score = score_for([finding(severity: "critical", confidence: "high")])
    assert_in_delta 86, score["score"], 2
  end

  def test_info_severity_barely_moves_the_score_even_with_several_findings
    findings = Array.new(10) { finding(severity: "info", confidence: "medium") }
    score = score_for(findings)

    assert_operator score["score"], :>=, 98
    assert_equal "A", score["grade"]
  end

  def test_info_impacts_the_score_far_less_than_warning_which_impacts_it_far_less_than_critical
    info_score = score_for([finding(severity: "info", confidence: "high")])["score"]
    warning_score = score_for([finding(severity: "warning", confidence: "high")])["score"]
    critical_score = score_for([finding(severity: "critical", confidence: "high")])["score"]

    assert_operator info_score, :>, warning_score
    assert_operator warning_score, :>, critical_score
    # Info's penalty (severity weight 0.25) is a small fraction of warning's
    # (weight 6) at the same confidence — the score gap should reflect that
    # rather than info being just a slightly gentler warning.
    assert_operator 100 - info_score, :<, (100 - warning_score) / 4
  end

  def test_many_info_findings_still_eventually_move_the_score_down
    findings = Array.new(200) { finding(severity: "info", confidence: "high") }
    score = score_for(findings)

    assert_operator score["score"], :<, 100
  end

  def test_low_confidence_costs_less_than_high_confidence_at_the_same_severity
    high = score_for([finding(severity: "warning", confidence: "high")])["score"]
    low = score_for([finding(severity: "warning", confidence: "low")])["score"]

    assert_operator low, :>, high
  end

  def test_dependency_findings_count_toward_the_score_even_without_a_confidence_field
    dependency_finding = Scryer::DependencyAudit::Finding.new(kind: "vulnerable_dependency", gem_name: "rails", severity: "critical")
    score = score_for([], dependency_findings: [dependency_finding])

    assert_operator score["score"], :<, 100
  end

  def test_style_findings_never_affect_the_score
    score = score_for([], style_findings: [finding(severity: "critical", rule_id: "frozen_string_literal", category: "style")])

    assert_equal 100, score["score"]
  end

  def test_duplicate_groups_never_affect_the_score
    group = Scryer::DuplicateDetector::DuplicateGroup.new(kind: "method_duplicate", similarity: 0.95, members: [])
    result = result_with([]).tap { |r| r.duplicate_groups = [group] }
    score = Scryer::ReportRenderer.new(result: result, project_name: "test").security_score

    assert_equal 100, score["score"]
  end

  def test_performance_findings_now_affect_the_score_but_far_less_than_security
    performance_score = score_for([], performance_findings: [finding(severity: "warning", confidence: "high", rule_id: "n_plus_one_query", category: "performance")])["score"]
    security_score = score_for([finding(severity: "warning", confidence: "high")])["score"]

    refute_equal 100, performance_score, "a performance finding should nudge the score, not leave it untouched"
    assert_operator performance_score, :>, security_score, "the same severity/confidence should cost far less as a performance finding than as a security one"
  end

  def test_finding_count_includes_performance_findings_too
    dependency_finding = Scryer::DependencyAudit::Finding.new(kind: "vulnerable_dependency", gem_name: "rails", severity: "warning")
    score = score_for(
      [finding(severity: "info")],
      dependency_findings: [dependency_finding],
      performance_findings: [finding(severity: "warning", rule_id: "n_plus_one_query", category: "performance")]
    )

    assert_equal 3, score["finding_count"]
  end
end
