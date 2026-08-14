require "json"
require "fileutils"

# Deliberately does NOT depend on the Rails `:environment` task — the
# scanning engine itself needs no Rails/bundler to run, so this task works
# equally via `bin/rails scryer:report` inside a Rails app or plain
# `bundle exec rake -f <this file> scryer:report` outside one. Avoids
# ActiveSupport methods (`.presence`/`.blank?`) for the same reason — plain
# Ruby nil-or-empty checks only.
namespace :scryer do
  desc "Run Scryer and write a report. Args are any mix of json/html/csv/sarif (which formats " \
       "to write — default json,html), the token 'nodeps' (skip the dependency audit — OSV.dev " \
       "vulnerable gems + insecure git/http sources — that otherwise runs by default; use for a " \
       "fast, fully offline run), plus at most one path (a directory when writing more than one " \
       "format, or an exact file for a single format). Rake splits bracket args on every comma, " \
       "so pass each token as its own item rather than one comma-joined string. " \
       "e.g. rails scryer:report, rails 'scryer:report[html]', " \
       "rails 'scryer:report[json,doc/security.json]', rails 'scryer:report[json,html]', " \
       "rails 'scryer:report[html,nodeps]', rails 'scryer:report[csv]', rails 'scryer:report[sarif]'. " \
       "Set SCRYER_BASELINE=PATH (an env var, not a bracket arg — see scryer:save_baseline) to " \
       "report only findings new since that baseline was saved."
  task :report, [:format] do |_, args|
    root = defined?(Rails) ? Rails.root.to_s : Dir.pwd
    dirs = Scryer.configuration.dirs

    # Ignore the declared :format name and read every positional value Rake
    # was given (args.to_a) — the whole point is accepting a variable number
    # of format/nodeps tokens plus one path, which a single named param can't do.
    formats, path_arg, run_deps = parse_report_args(args.to_a)

    skip_rules = Scryer.configuration.skip_rules
    puts "Scryer: skipping #{skip_rules.join(', ')}." if skip_rules.any?

    result = Scryer::Scanner.new(root: root, dirs: dirs, skip_rules: skip_rules).call

    # Dependency auditing (OSV.dev) runs by default — a single scryer:report
    # run is meant to cover the same ground as RuboCop + Brakeman +
    # bundler-audit + Reek run separately. Pass the 'nodeps' token for a
    # fast, fully offline run instead.
    dependency_findings = []
    if run_deps
      puts "Scryer: querying OSV.dev for known-vulnerable gems (needs network)..."
      dependency_findings = Scryer::DependencyAudit.insecure_sources(root) + Scryer::DependencyAudit.vulnerable_gems(root) +
                             Scryer::DependencyAudit.ruby_eol_check(root) + Scryer::DependencyAudit.credentials_exposure_check(root)
    end

    # Rake bracket args are already stretched thin (format tokens + nodeps +
    # one output path) — an ENV var is the more conventional way Rails rake
    # tasks take an extra config value without overloading positional args
    # further. `rails 'scryer:save_baseline[tmp/scryer_baseline.json]'` writes
    # one; `SCRYER_BASELINE=tmp/scryer_baseline.json rails scryer:report`
    # reads it back. See Scryer::Baseline / the CLI's --baseline flag for
    # what this actually does (fingerprint-based new-vs-fixed diffing, not
    # tied to line number).
    baseline_path = blank_to_nil(ENV["SCRYER_BASELINE"])
    fixed_count = 0
    if baseline_path
      dependency_findings, fixed_count = ScryerTasks.apply_baseline(baseline_path, result, dependency_findings)
    end

    if Scryer.configuration.ai_client
      puts "Scryer: rewriting suggested fixes via the configured AI client..."
      Scryer::AiFixSuggester.enhance_result!(result, root: root)
      Scryer::AiFixSuggester.enhance_many!(dependency_findings) unless dependency_findings.empty?
    end

    renderer = Scryer::ReportRenderer.new(
      result: result,
      project_name: blank_to_nil(Scryer.configuration.project_name) || File.basename(root),
      release_label: ScryerTasks.git_release_label,
      git_commit_sha: ScryerTasks.git_commit_sha,
      git_branch: blank_to_nil(Scryer.configuration.branch) || ScryerTasks.git_branch,
      dependency_findings: dependency_findings
    )

    paths = output_paths(root: root, formats: formats, path_arg: path_arg)

    paths.each do |format, path|
      FileUtils.mkdir_p(File.dirname(path))
      content = case format
                when "json" then renderer.as_json
                when "csv" then renderer.as_csv
                when "sarif" then renderer.as_sarif
                else renderer.as_html
                end
      File.write(path, content)
    end

    ScryerTasks.print_summary(result: result, dependency_findings: dependency_findings, ran_deps: run_deps, paths: paths,
                               renderer: renderer, fixed_count: fixed_count, baseline_path: baseline_path)

    # Same gate as the `scryer` executable and scryer:audit_dependencies
    # below: fail the task (and so the CI job running it) on any security or
    # dependency finding, so `bin/rails scryer:report` gates a build the
    # same way `brakeman` or `bundle-audit check` would. Performance/style
    # findings are advisory only and never fail the task.
    if result.security_findings.any? || dependency_findings.any?
      abort("Scryer: found #{result.security_findings.size} security finding(s) and " \
            "#{dependency_findings.size} dependency finding(s).")
    end
  end

  desc "Convenience wrapper for CI: runs scryer:report with CI-sensible defaults — JSON + " \
       "SARIF written under tmp/ (SARIF for GitHub Code Scanning / similar dashboards, JSON as " \
       "the machine-readable form other CI steps can parse), dependency audit on, same " \
       "SCRYER_BASELINE support and same fail-the-build-on-findings behavior as scryer:report. " \
       "Equivalent to `rails 'scryer:report[json,sarif]'` under a name that doesn't require " \
       "remembering the bracket-arg syntax. e.g. rails scryer:ci"
  task :ci do
    Rake::Task["scryer:report"].invoke("json", "sarif")
  end

  desc "Run Scryer and save every finding's fingerprint to PATH, for later comparison via " \
       "SCRYER_BASELINE=PATH rails scryer:report (see that task's SCRYER_BASELINE note). " \
       "Runs the same scan as scryer:report (including the dependency audit) but writes no " \
       "report files. e.g. rails 'scryer:save_baseline[tmp/scryer_baseline.json]'"
  task :save_baseline, [:path] do |_, args|
    path = args[:path] || abort("Scryer: scryer:save_baseline needs a path, " \
                                 "e.g. rails 'scryer:save_baseline[tmp/scryer_baseline.json]'")
    root = defined?(Rails) ? Rails.root.to_s : Dir.pwd
    dirs = Scryer.configuration.dirs

    result = Scryer::Scanner.new(root: root, dirs: dirs, skip_rules: Scryer.configuration.skip_rules).call
    puts "Scryer: querying OSV.dev for known-vulnerable gems (needs network)..."
    dependency_findings = Scryer::DependencyAudit.insecure_sources(root) + Scryer::DependencyAudit.vulnerable_gems(root) +
                           Scryer::DependencyAudit.ruby_eol_check(root) + Scryer::DependencyAudit.credentials_exposure_check(root)

    all_findings = (result.security_findings + result.performance_findings + result.style_findings).map(&:to_h) +
                   dependency_findings.map(&:to_h)
    Scryer::Baseline.save(path, all_findings)
    puts "Scryer: saved baseline of #{all_findings.size} finding(s) to #{path}."
  end

  desc "Check Gemfile.lock for known-vulnerable gem versions (via OSV.dev — needs network) " \
       "and insecure git/http gem sources (offline). Exits non-zero if anything is found, so " \
       "this can gate CI the same way `bundle-audit check` does."
  task :audit_dependencies do
    root = defined?(Rails) ? Rails.root.to_s : Dir.pwd

    puts "Scryer: checking Gemfile.lock sources (offline)..."
    insecure = Scryer::DependencyAudit.insecure_sources(root)

    puts "Scryer: querying OSV.dev for known vulnerabilities (needs network)..."
    vulnerable = Scryer::DependencyAudit.vulnerable_gems(root)
    ruby_eol = Scryer::DependencyAudit.ruby_eol_check(root)
    credentials_exposure = Scryer::DependencyAudit.credentials_exposure_check(root)

    (insecure + vulnerable + ruby_eol + credentials_exposure).each do |f|
      puts "[#{f.severity.upcase}] #{ScryerTasks.dependency_label(f)}"
      puts "  fix: #{f.suggested_fix}"
    end

    total = insecure.size + vulnerable.size + ruby_eol.size + credentials_exposure.size
    puts "\nScryer: #{total} dependency finding(s) (#{insecure.size} insecure source, " \
         "#{vulnerable.size} vulnerable gem, #{ruby_eol.size} Ruby EOL, " \
         "#{credentials_exposure.size} credentials exposure)."
    abort("Scryer: dependency audit failed.") if total.positive?
  end

  VALID_FORMATS = %w[json html csv sarif].freeze
  EXTENSION_FOR_FORMAT = { "json" => "json", "html" => "html", "csv" => "csv", "sarif" => "sarif" }.freeze
  NO_DEPS_TOKEN = "nodeps".freeze

  # tokens is every bracket arg Rake was given, e.g. %w[json doc/security.json] or
  # %w[json html] or %w[html nodeps] or []. Returns [formats, path_arg,
  # run_deps] — any token matching a known format is a format, the literal
  # "nodeps" token opts *out* of the dependency audit that otherwise runs by
  # default, and at most one other token is allowed, which is the path.
  def parse_report_args(tokens)
    tokens = tokens.map { |t| blank_to_nil(t) }.compact
    run_deps = tokens.none? { |t| t.downcase == NO_DEPS_TOKEN }
    tokens = tokens.reject { |t| t.downcase == NO_DEPS_TOKEN }

    format_tokens, other_tokens = tokens.partition { |t| VALID_FORMATS.include?(t.downcase) }

    if other_tokens.size > 1
      abort "Scryer: only one path is allowed — got #{other_tokens.join(', ')}."
    end

    formats = format_tokens.map(&:downcase).uniq
    formats = %w[json html] if formats.empty?

    [formats, other_tokens.first, run_deps]
  end

  # No path given: default filenames under tmp/. A path given with a single
  # format whose extension matches that format is treated as an exact file
  # target; otherwise the path is treated as a directory (created if needed)
  # and each format gets its default filename inside it.
  def output_paths(root:, formats:, path_arg:)
    default_names = formats.each_with_object({}) { |f, h| h[f] = "scryer_report.#{EXTENSION_FOR_FORMAT[f]}" }
    return default_names.transform_values { |name| File.join(root, "tmp", name) } if path_arg.nil?

    resolved = File.absolute_path?(path_arg) ? path_arg : File.join(root, path_arg)
    ext = File.extname(resolved).delete_prefix(".").downcase

    if formats.size == 1 && ext == formats.first
      { formats.first => resolved }
    else
      formats.each_with_object({}) { |f, h| h[f] = File.join(resolved, default_names[f]) }
    end
  end

  def blank_to_nil(value)
    return nil if value.nil?

    str = value.to_s.strip
    str.empty? ? nil : str
  end
end

module ScryerTasks
  module_function

  def git_commit_sha
    shell_out("git rev-parse HEAD")
  end

  def git_branch
    shell_out("git rev-parse --abbrev-ref HEAD")
  end

  def git_release_label
    shell_out("git describe --tags --always")
  end

  def shell_out(cmd)
    output = `#{cmd} 2>/dev/null`.strip
    output.empty? ? nil : output
  rescue StandardError
    nil
  end

  def dependency_label(f)
    return f.message if f.kind == "insecure_source"
    return "#{f.gem_name} #{f.installed_version} - #{f.advisory_id}: #{f.title}" if f.advisory_id

    "#{f.gem_name} #{f.installed_version}: #{f.title}"
  end

  # Same logic as Scryer::CLI#apply_baseline (see that method's comment for
  # why fixed_count has to be computed once against the combined set of
  # every category's current fingerprints, not once per category summed).
  def apply_baseline(path, result, dependency_findings)
    baseline_fingerprints = Scryer::Baseline.load(path)

    security_hashes = result.security_findings.map(&:to_h)
    performance_hashes = result.performance_findings.map(&:to_h)
    style_hashes = result.style_findings.map(&:to_h)
    dependency_hashes = dependency_findings.map(&:to_h)

    all_current_fingerprints = Scryer::Baseline.fingerprints(security_hashes + performance_hashes + style_hashes + dependency_hashes)
    fixed_count = (baseline_fingerprints - all_current_fingerprints.to_set).size

    result.security_findings = filter_new(result.security_findings, security_hashes, baseline_fingerprints)
    result.performance_findings = filter_new(result.performance_findings, performance_hashes, baseline_fingerprints)
    result.style_findings = filter_new(result.style_findings, style_hashes, baseline_fingerprints)
    filtered_deps = filter_new(dependency_findings, dependency_hashes, baseline_fingerprints)

    [filtered_deps, fixed_count]
  rescue Scryer::Baseline::LoadError => e
    abort("Scryer: #{e.message}")
  end

  def filter_new(objects, hashes, baseline_fingerprints)
    fingerprints = Scryer::Baseline.fingerprints(hashes)
    objects.each_with_index.reject { |_, i| baseline_fingerprints.include?(fingerprints[i]) }.map(&:first)
  end

  # The "one audit command" summary — a single scan's worth of every
  # category Scryer covers (security, performance, duplicate/smelly code,
  # dependencies), the same categories usually split across RuboCop +
  # Brakeman + bundler-audit + Reek, side by side in one box.
  def print_summary(result:, dependency_findings:, ran_deps:, paths:, renderer:, fixed_count: 0, baseline_path: nil)
    # "Code Quality" is the umbrella label for both duplicate-code groups
    # and rule-based style findings (e.g. frozen_string_literal) — two
    # different detectors, same broad concern, one row in the box.
    code_quality = result.duplicate_groups.size + result.style_findings.size
    deps_count = ran_deps ? dependency_findings.size : nil
    total = result.security_findings.size + result.performance_findings.size + code_quality + (deps_count || 0)

    rows = [
      ["Security", result.security_findings.size],
      ["Performance", result.performance_findings.size],
      ["Code Quality", code_quality],
      ["Dependencies", deps_count]
    ]

    divider = "─" * 32
    score = renderer.security_score
    puts ""
    puts "Scryer Audit — #{result.files_scanned} files scanned"
    puts divider
    puts ""
    if baseline_path
      puts "Baseline: #{baseline_path} — showing new findings only (#{fixed_count} fixed since baseline)."
      puts ""
    end
    clean_rate = renderer.rules_clean_rate
    puts "Security Score: #{score["score"]}/100 (#{score["grade"]})"
    puts "Checks: #{clean_rate["clean"]}/#{clean_rate["total"]} rules clean (#{clean_rate["percent"]}%)"
    puts ""
    rows.each { |label, count| puts summary_row(label, count) }
    puts divider
    puts summary_row("Total", total)
    puts ""
    print_top_priorities(renderer.top_risks)
    print_owasp_coverage(renderer.owasp_coverage)
    paths.each { |format, path| puts "#{format.upcase} report: #{path}" }
  end

  def summary_row(label, count)
    value = count.nil? ? "skipped (nodeps)" : "#{count} finding#{"s" unless count == 1}"
    "#{label.ljust(14)}#{value.rjust(20)}"
  end

  # The categories above are counted separately, but nothing else ranks
  # across them — this is what actually backs "tells you what to fix
  # first" rather than just splitting findings into four buckets. Same
  # data ReportRenderer#top_risks already sorts for the HTML report.
  def print_top_priorities(risks)
    return if risks.empty?

    puts "Top priorities:"
    risks.each_with_index do |r, i|
      puts "  #{i + 1}. [#{r[:severity]}] #{r[:category]} — #{r[:label]} (#{r[:location]})"
    end
    puts ""
  end

  # Byproduct of every security rule carrying an owasp_category — see
  # ReportRenderer#owasp_coverage. Scryer's own best-effort tagging, not an
  # OWASP-audited mapping (documented in full in the README).
  def print_owasp_coverage(coverage)
    return if coverage.empty?

    puts "OWASP Top 10 (2021) coverage:"
    coverage.each { |category, count| puts "  #{category}: #{count} finding#{"s" unless count == 1}" }
    puts ""
  end
end
