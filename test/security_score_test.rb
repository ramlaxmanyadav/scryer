require_relative "test_helper"

# Scryer::ReportRenderer's four independent category scores
# (#security_score/#performance_score/#style_score/#dependency_score) — no
# prior test file covered the score formula at all before these existed.
# Locks in the severity/confidence weights
# (Scryer::ReportRenderer::SCORE_SEVERITY_WEIGHT/SCORE_CONFIDENCE_WEIGHT) so a
# future change to them is a deliberate, visible diff here rather than a
# silent drift in what the scores mean — and, just as important, locks in
# that the four scores are genuinely independent: a finding in one category
# must never move another category's score.
class CategoryScoreTest < Minitest::Test
  def finding(severity:, confidence: "medium", rule_id: "sql_injection", category: "security")
    Scryer::Finding.new(
      rule_id: rule_id, category: category, severity: severity, confidence: confidence,
      cwe: "CWE-89", owasp_category: "A03:2021-Injection", file: "app/models/x.rb", line: 1,
      code_snippet: "x", message: "example", suggested_fix: "example"
    )
  end

  def dependency_finding(severity: "critical")
    Scryer::DependencyAudit::Finding.new(kind: "vulnerable_dependency", gem_name: "rails", severity: severity)
  end

  def renderer_for(security: [], performance: [], style: [], dependency: [])
    result = Scryer::Scanner::Result.new(
      security_findings: security, performance_findings: performance, style_findings: style,
      duplicate_groups: [], files_scanned: 1, parse_errors: []
    )
    Scryer::ReportRenderer.new(result: result, project_name: "test", dependency_findings: dependency)
  end

  def test_a_clean_scan_scores_100_a_on_every_category
    renderer = renderer_for
    %i[security_score performance_score style_score dependency_score].each do |method|
      score = renderer.public_send(method)
      assert_equal 100, score["score"], "#{method} should be 100 on a clean scan"
      assert_equal "A", score["grade"]
      assert_equal 0, score["finding_count"]
    end
  end

  def test_a_single_high_confidence_critical_finding_visibly_moves_the_score
    renderer = renderer_for(security: [finding(severity: "critical", confidence: "high")])
    assert_in_delta 86, renderer.security_score["score"], 2
  end

  def test_info_severity_barely_moves_the_score_even_with_several_findings
    findings = Array.new(10) { finding(severity: "info", confidence: "medium") }
    renderer = renderer_for(security: findings)

    assert_operator renderer.security_score["score"], :>=, 98
    assert_equal "A", renderer.security_score["grade"]
  end

  def test_info_impacts_the_score_far_less_than_warning_which_impacts_it_far_less_than_critical
    info_score = renderer_for(security: [finding(severity: "info", confidence: "high")]).security_score["score"]
    warning_score = renderer_for(security: [finding(severity: "warning", confidence: "high")]).security_score["score"]
    critical_score = renderer_for(security: [finding(severity: "critical", confidence: "high")]).security_score["score"]

    assert_operator info_score, :>, warning_score
    assert_operator warning_score, :>, critical_score
    # Info's penalty (severity weight 0.25) is a small fraction of warning's
    # (weight 6) at the same confidence — the score gap should reflect that
    # rather than info being just a slightly gentler warning.
    assert_operator 100 - info_score, :<, (100 - warning_score) / 4
  end

  def test_many_info_findings_still_eventually_move_the_score_down
    findings = Array.new(200) { finding(severity: "info", confidence: "high") }
    assert_operator renderer_for(security: findings).security_score["score"], :<, 100
  end

  def test_low_confidence_costs_less_than_high_confidence_at_the_same_severity
    high = renderer_for(security: [finding(severity: "warning", confidence: "high")]).security_score["score"]
    low = renderer_for(security: [finding(severity: "warning", confidence: "low")]).security_score["score"]

    assert_operator low, :>, high
  end

  def test_duplicate_groups_never_affect_any_score
    group = Scryer::DuplicateDetector::DuplicateGroup.new(kind: "method_duplicate", similarity: 0.95, members: [])
    renderer = renderer_for
    renderer.instance_variable_get(:@result).duplicate_groups = [group]

    assert_equal 100, renderer.security_score["score"]
    assert_equal 100, renderer.style_score["score"]
  end

  # The core independence guarantee: a finding in one category runs through
  # the exact same formula as security_score (same weights, same math), but
  # must never leak into, dilute, or otherwise affect any *other*
  # category's score. This used to not be true at all — a single blended
  # security_score folded performance findings in at a diluted weight and
  # dropped style findings entirely — which is the whole reason these four
  # independent methods exist now.
  def test_each_category_score_is_computed_independently_of_the_others
    critical = finding(severity: "critical", confidence: "high")

    security_only = renderer_for(security: [critical])
    performance_only = renderer_for(performance: [critical.dup.tap { |f| f.category = "performance" }])
    style_only = renderer_for(style: [critical.dup.tap { |f| f.category = "style" }])
    dependency_only = renderer_for(dependency: [dependency_finding(severity: "critical")])

    # Each one's own score moves...
    assert_operator security_only.security_score["score"], :<, 100
    assert_operator performance_only.performance_score["score"], :<, 100
    assert_operator style_only.style_score["score"], :<, 100
    assert_operator dependency_only.dependency_score["score"], :<, 100

    # ...and the exact same critical/high-confidence finding costs an
    # identical amount regardless of which category it's scoped to — no
    # per-category dilution factor anymore. (Dependency findings have no
    # `confidence` field at all — see DependencyAudit::Finding — so they
    # always fall through to the same default weight as a medium-confidence
    # finding; excluded from this specific comparison for that reason, not
    # because dependency_score itself works any differently.)
    assert_equal security_only.security_score["score"], performance_only.performance_score["score"]
    assert_equal security_only.security_score["score"], style_only.style_score["score"]

    # ...but none of the *other* three scores move at all.
    assert_equal 100, security_only.performance_score["score"]
    assert_equal 100, security_only.style_score["score"]
    assert_equal 100, security_only.dependency_score["score"]
    assert_equal 100, performance_only.security_score["score"]
    assert_equal 100, style_only.security_score["score"]
    assert_equal 100, dependency_only.security_score["score"]
  end

  def test_dependency_findings_count_toward_the_dependency_score_even_without_a_confidence_field
    renderer = renderer_for(dependency: [dependency_finding(severity: "critical")])
    assert_operator renderer.dependency_score["score"], :<, 100
    assert_equal 1, renderer.dependency_score["finding_count"]
  end

  def test_finding_count_is_scoped_to_its_own_category_only
    renderer = renderer_for(
      security: [finding(severity: "info"), finding(severity: "warning")],
      performance: [finding(severity: "warning", rule_id: "n_plus_one_query", category: "performance")],
      style: [finding(severity: "info", rule_id: "frozen_string_literal", category: "style")],
      dependency: [dependency_finding]
    )

    assert_equal 2, renderer.security_score["finding_count"]
    assert_equal 1, renderer.performance_score["finding_count"]
    assert_equal 1, renderer.style_score["finding_count"]
    assert_equal 1, renderer.dependency_score["finding_count"]
  end

  def test_as_hash_includes_all_four_scores
    renderer = renderer_for(security: [finding(severity: "critical")])
    h = renderer.as_hash

    assert_equal renderer.security_score, h["security_score"]
    assert_equal renderer.performance_score, h["performance_score"]
    assert_equal renderer.style_score, h["style_score"]
    assert_equal renderer.dependency_score, h["dependency_score"]
  end
end
