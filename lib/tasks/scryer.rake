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
       "fast, fully offline run), the token 'noduplicates' (skip duplicate-code detection for " \
       "this run only, regardless of c.detect_duplicates), plus at most one path (a directory " \
       "when writing more than one format, or an exact file for a single format). Rake splits " \
       "bracket args on every comma, so pass each token as its own item rather than one " \
       "comma-joined string. e.g. rails scryer:report, rails 'scryer:report[html]', " \
       "rails 'scryer:report[json,doc/security.json]', rails 'scryer:report[json,html]', " \
       "rails 'scryer:report[html,nodeps]', rails 'scryer:report[html,noduplicates]', " \
       "rails 'scryer:report[csv]', rails 'scryer:report[sarif]'. " \
       "Set SCRYER_BASELINE=PATH (an env var, not a bracket arg — see scryer:save_baseline) to " \
       "report only findings new since that baseline was saved."
  task :report, [:format] do |_, args|
    root = defined?(Rails) ? Rails.root.to_s : Dir.pwd
    dirs = Scryer.configuration.dirs

    # Ignore the declared :format name and read every positional value Rake
    # was given (args.to_a) — the whole point is accepting a variable number
    # of format/nodeps/noduplicates tokens plus one path, which a single
    # named param can't do.
    formats, path_arg, run_deps, detect_duplicates = parse_report_args(args.to_a)

    skip_rules = Scryer.configuration.skip_rules
    puts "Scryer: skipping #{skip_rules.join(', ')}." if skip_rules.any?

    result = Scryer::Scanner.new(root: root, dirs: dirs, skip_rules: skip_rules, detect_duplicates: detect_duplicates).call

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

    # detect_duplicates: false — a baseline never includes duplicate_groups
    # (see all_findings below and Scryer::CLI#apply_baseline's own comment
    # on why), so there's nothing to gain from that pass here.
    result = Scryer::Scanner.new(root: root, dirs: dirs, skip_rules: Scryer.configuration.skip_rules, detect_duplicates: false).call
    puts "Scryer: querying OSV.dev for known-vulnerable gems (needs network)..."
    dependency_findings = Scryer::DependencyAudit.insecure_sources(root) + Scryer::DependencyAudit.vulnerable_gems(root) +
                           Scryer::DependencyAudit.ruby_eol_check(root) + Scryer::DependencyAudit.credentials_exposure_check(root)

    all_findings = (result.security_findings + result.performance_findings + result.style_findings).map(&:to_h) +
                   dependency_findings.map(&:to_h)
    Scryer::Baseline.save(path, all_findings)
    puts "Scryer: saved baseline of #{all_findings.size} finding(s) to #{path}."
  end

  desc "Scan, then ask the configured c.ai_client for a rewrite of every qualifying finding and " \
       "write the ones independently verified to actually clear it (see Scryer::FixVerifier) — " \
       "requires c.ai_client to be set (config/initializers/scryer.rb); anything not verified is " \
       "left alone and reported for manual review, same as a normal report would show it. Takes " \
       "an optional rule_id bracket arg to only fix that rule; set SCRYER_FIX_DRY_RUN=1 to preview " \
       "without writing anything, SCRYER_FIX_LIST=1 to print the numbered candidates and exit, " \
       "SCRYER_FIX_NUMBERS=1,3 to only fix those numbered positions (see SCRYER_FIX_LIST), or " \
       "SCRYER_FIX_YES=1 to skip the per-finding accept/skip prompt this task otherwise shows in " \
       "an interactive terminal, or SCRYER_FIX_DEPS=1 to fix vulnerable dependencies instead " \
       "(runs `bundle update GEM --conservative` per vulnerable gem with a published patched " \
       "version, then re-checks OSV.dev — see Scryer::DependencyFixer; ignores the rule_id arg " \
       "and SCRYER_FIX_LIST/SCRYER_FIX_NUMBERS, which only make sense for rule-based findings). " \
       "e.g. rails scryer:fix, rails 'scryer:fix[sql_injection]', " \
       "SCRYER_FIX_DRY_RUN=1 rails scryer:fix, SCRYER_FIX_DEPS=1 rails scryer:fix"
  task :fix, [:rule_id] do |_, args|
    root = defined?(Rails) ? Rails.root.to_s : Dir.pwd
    dry_run = !blank_to_nil(ENV["SCRYER_FIX_DRY_RUN"]).nil?

    if !blank_to_nil(ENV["SCRYER_FIX_DEPS"]).nil?
      puts "Scryer: querying OSV.dev for known-vulnerable gems (needs network)..."
      findings = Scryer::DependencyAudit.vulnerable_gems(root)

      if findings.empty?
        puts "Scryer: no vulnerable gems found."
        next
      end

      actionable = findings.select { |f| Array(f.patched_versions).any? }
      if actionable.empty?
        puts "Scryer: #{findings.size} vulnerable gem finding(s), but none have a published " \
             "patched version yet to upgrade to — nothing this task can run. See " \
             "`rails scryer:audit_dependencies` for details."
        next
      end

      gem_count = actionable.map(&:gem_name).uniq.size
      puts "Scryer: #{actionable.size} finding(s) across #{gem_count} gem(s) — running " \
           "`bundle update GEM --conservative` for each" \
           "#{dry_run ? " (SCRYER_FIX_DRY_RUN: nothing will actually run)" : ""}..."

      fixed, skipped = Scryer::DependencyFixer.apply(findings, root: root, dry_run: dry_run) do |finding, status, error|
        ScryerTasks.print_deps_fix_progress(finding, status, error)
      end
      ScryerTasks.print_deps_fix_summary(fixed: fixed, skipped: skipped, dry_run: dry_run)

      abort("Scryer: #{skipped.size} finding(s) not applied.") if !dry_run && skipped.any?
      next
    end

    ai_client = Scryer.configuration.ai_client
    dirs = Scryer.configuration.dirs
    skip_rules = Scryer.configuration.skip_rules
    list_only = !blank_to_nil(ENV["SCRYER_FIX_LIST"]).nil?
    yes = !blank_to_nil(ENV["SCRYER_FIX_YES"]).nil?
    numbers = blank_to_nil(ENV["SCRYER_FIX_NUMBERS"])&.split(",")&.map(&:strip)

    # detect_duplicates: false — candidates below are only ever
    # security/performance/style findings; a duplicate-code group has no
    # rule_id/single-line suggested_fix for FixRunner to act on.
    result = Scryer::Scanner.new(root: root, dirs: dirs, skip_rules: skip_rules, detect_duplicates: false).call
    candidates = result.security_findings + result.performance_findings + result.style_findings
    candidates = candidates.select { |f| f.rule_id == args[:rule_id] } if args[:rule_id]
    candidates = candidates.sort_by { |f| [f.file.to_s, f.line || 0] }

    if candidates.empty?
      puts "Scryer: no matching findings to fix."
      next
    end

    if list_only
      ScryerTasks.print_candidate_list(candidates)
      next
    end

    candidates = ScryerTasks.gate_frozen_string_literal(candidates, explicit: !args[:rule_id].nil?)
    if candidates.empty?
      puts "Scryer: no matching findings to fix."
      next
    end

    candidates = ScryerTasks.select_by_number(candidates, numbers) if numbers

    # See Scryer::MechanicalFixer — a handful of rules have exactly one
    # correct fix and don't need c.ai_client at all. Only abort when
    # there's genuinely nothing this run could fix: no ai_client AND
    # nothing matched has a built-in fixer.
    if ai_client.nil? && candidates.none? { |f| Scryer::MechanicalFixer.supported?(f.rule_id) }
      abort("Scryer: scryer:fix needs c.ai_client configured in config/initializers/scryer.rb — " \
            "none of the matched finding(s) have a built-in mechanical fixer " \
            "(#{Scryer::MechanicalFixer::SUPPORTED_RULES.join(", ")}), and a rule's generic " \
            "suggested_fix is prose, not something this task can apply automatically on its own. " \
            "Nothing has been changed.")
    end

    # See ScryerTasks#build_fix_confirmer / Scryer::CLI#build_fix_confirmer:
    # in an interactive terminal (and not dry-run/SCRYER_FIX_YES), review
    # each verified fix one at a time before writing it.
    confirm = ScryerTasks.build_fix_confirmer if $stdin.respond_to?(:tty?) && $stdin.tty? && !dry_run && !yes

    puts "Scryer: #{candidates.size} candidate finding(s) — applying built-in fixes where one " \
         "exists, otherwise asking the configured AI client for a rewrite; either way, only " \
         "writing what's independently verified to clear the finding" \
         "#{dry_run ? " (SCRYER_FIX_DRY_RUN: nothing will actually be written)" : ""}..."

    fixed, skipped = Scryer::FixRunner.apply(candidates, client: ai_client, root: root, dry_run: dry_run, confirm: confirm) do |finding, status, error|
      ScryerTasks.print_fix_progress(finding, status, error)
    end
    ScryerTasks.print_fix_summary(fixed: fixed, skipped: skipped, dry_run: dry_run)

    if !dry_run && fixed.any?
      puts "Scryer: re-scanning to verify every applied fix..."
      regressed = Scryer::FixRunner.verify(fixed, root: root, dirs: dirs, skip_rules: skip_rules)
      ScryerTasks.print_fix_verification(regressed, total: fixed.size)
    end

    abort("Scryer: #{skipped.size} finding(s) still need manual review.") if !dry_run && skipped.any?
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
      puts "[#{ScryerTasks.paint_severity(f.severity.upcase, f.severity)}] #{ScryerTasks.dependency_label(f)}"
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
  NO_DUPLICATES_TOKEN = "noduplicates".freeze

  # tokens is every bracket arg Rake was given, e.g. %w[json doc/security.json] or
  # %w[json html] or %w[html nodeps] or []. Returns [formats, path_arg,
  # run_deps, detect_duplicates] — any token matching a known format is a
  # format, the literal "nodeps" token opts *out* of the dependency audit
  # that otherwise runs by default, the literal "noduplicates" token opts
  # out of duplicate-code detection for this run only (c.detect_duplicates
  # already off is still off either way — this token can only turn it off,
  # never back on), and at most one other token is allowed, which is the
  # path.
  def parse_report_args(tokens)
    tokens = tokens.map { |t| blank_to_nil(t) }.compact
    run_deps = tokens.none? { |t| t.downcase == NO_DEPS_TOKEN }
    detect_duplicates = Scryer.configuration.detect_duplicates && tokens.none? { |t| t.downcase == NO_DUPLICATES_TOKEN }
    tokens = tokens.reject { |t| [NO_DEPS_TOKEN, NO_DUPLICATES_TOKEN].include?(t.downcase) }

    format_tokens, other_tokens = tokens.partition { |t| VALID_FORMATS.include?(t.downcase) }

    if other_tokens.size > 1
      abort "Scryer: only one path is allowed — got #{other_tokens.join(', ')}."
    end

    formats = format_tokens.map(&:downcase).uniq
    formats = %w[json html] if formats.empty?

    [formats, other_tokens.first, run_deps, detect_duplicates]
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

  # SCRYER_COLOR/SCRYER_NO_COLOR are this task's equivalent of the CLI's
  # --color/--no-color — an explicit env var wins over Scryer::Colorizer's
  # own NO_COLOR/TTY auto-detection either way, same precedence the CLI
  # flags use (see Scryer::Colorizer's own comment for why).
  def color_override
    return true unless blank_to_nil(ENV["SCRYER_COLOR"]).nil?
    return false unless blank_to_nil(ENV["SCRYER_NO_COLOR"]).nil?

    nil
  end

  def paint(text, *styles)
    Scryer::Colorizer.paint(text, *styles, stream: $stdout, override: color_override)
  end

  def paint_severity(text, severity)
    Scryer::Colorizer.severity(text, severity, stream: $stdout, override: color_override)
  end

  def paint_grade(text, letter)
    Scryer::Colorizer.grade(text, letter, stream: $stdout, override: color_override)
  end

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

    divider = paint("─" * 32, :gray)
    score = renderer.security_score
    puts ""
    puts paint("Scryer Audit — #{result.files_scanned} files scanned", :bold)
    puts divider
    puts ""
    if baseline_path
      puts "Baseline: #{baseline_path} — showing new findings only (#{fixed_count} fixed since baseline)."
      puts ""
    end
    clean_rate = renderer.rules_clean_rate
    puts "Security Score: #{score["score"]}/100 (#{paint_grade(score["grade"], score["grade"])})"
    puts "Checks: #{clean_rate["clean"]}/#{clean_rate["total"]} rules clean (#{clean_rate["percent"]}%)"
    puts ""
    rows.each { |label, count| puts summary_row(label, count) }
    puts divider
    puts paint(summary_row("Total", total), :bold)
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

    puts paint("Top priorities:", :bold)
    risks.each_with_index do |r, i|
      puts "  #{i + 1}. [#{paint_severity(r[:severity], r[:severity])}] #{r[:category]} — #{r[:label]} (#{r[:location]})"
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

  # Same real-time progress line as Scryer::CLI#print_fix_progress.
  def print_fix_progress(finding, status, error = nil)
    label = { fixed: "Fixed", would_fix: "Would fix", declined: "Skipped (declined)",
              ai_error: "Skipped (AI client error)", cancelled: "Skipped (cancelled)",
              skipped: "Skipped (needs manual review)" }.fetch(status)
    colored_label = %i[fixed would_fix].include?(status) ? paint(label, :green, :bold) : paint(label, :yellow)
    puts "#{colored_label}: #{finding.rule_id} — #{finding.file}:#{finding.line}"

    if status == :ai_error && error
      puts "  #{paint("#{error.class}: #{error.message}", :red)}"
    else
      explanation = Scryer::FixRunner.explain(finding.suggested_fix)
      puts "  #{explanation}" unless explanation.empty?
    end
  end

  def print_fix_summary(fixed:, skipped:, dry_run:)
    verb = dry_run ? "Would fix" : "Fixed"
    puts ""
    puts paint("#{verb} #{fixed.size} finding(s):", :green, :bold)
    fixed.each { |f| puts "  #{f.rule_id} — #{f.file}:#{f.line}" }
    puts ""

    return if skipped.empty?

    puts paint("#{skipped.size} finding(s) not applied (declined, or fix not independently verified):", :yellow)
    skipped.each { |f| puts "  #{f.rule_id} — #{f.file}:#{f.line}" }
    puts ""
  end

  # Same real-time progress line as Scryer::CLI#print_deps_fix_progress —
  # SCRYER_FIX_DEPS's dependency-finding analog of print_fix_progress above.
  def print_deps_fix_progress(finding, status, error = nil)
    label = { fixed: "Fixed", would_fix: "Would fix", error: "Error running bundle update",
              skipped: "Skipped (needs manual review)" }.fetch(status)
    colored_label = %i[fixed would_fix].include?(status) ? paint(label, :green, :bold) : paint(label, :yellow)
    puts "#{colored_label}: #{finding.gem_name}#{finding.advisory_id ? " (#{finding.advisory_id})" : ""}"

    if error
      puts "  #{paint(error.to_s.strip, :red)}"
    elsif status == :skipped && finding.suggested_fix
      puts "  #{finding.suggested_fix}"
    end
  end

  def print_deps_fix_summary(fixed:, skipped:, dry_run:)
    verb = dry_run ? "Would fix" : "Fixed"
    puts ""
    puts paint("#{verb} #{fixed.size} finding(s):", :green, :bold)
    fixed.each { |f| puts "  #{f.gem_name}#{f.advisory_id ? " (#{f.advisory_id})" : ""}" }
    puts ""

    return if skipped.empty?

    puts paint("#{skipped.size} finding(s) not applied (no patched version yet, bundle update " \
               "failed, or the re-check still shows it vulnerable):", :yellow)
    skipped.each { |f| puts "  #{f.gem_name}#{f.advisory_id ? " (#{f.advisory_id})" : ""}" }
    puts ""
  end

  # Same real-time per-finding review as Scryer::CLI#build_fix_confirmer —
  # SCRYER_FIX_YES is this task's equivalent of the CLI's --yes. Numeric
  # choices only; "4" (cancel) returns :cancel, which FixRunner.apply treats
  # as "stop entirely" — see Scryer::FixRunner.apply's own doc comment.
  def build_fix_confirmer
    mode = :ask
    lambda do |finding|
      next true if mode == :all

      print_finding_preview(finding)
      loop do
        puts "Apply this fix?"
        puts "  1) Yes"
        puts "  2) Skip"
        puts "  3) Yes to all remaining"
        puts "  4) Cancel (stop reviewing — nothing further will be attempted)"
        print "Choice: "
        $stdout.flush
        case $stdin.gets.to_s.strip
        when "1" then break true
        when "2" then break false
        when "3" then mode = :all; break true
        when "4" then break :cancel
        else puts "Please enter 1, 2, 3, or 4."
        end
      end
    end
  end

  def print_finding_preview(finding)
    puts ""
    puts "#{finding.rule_id} — #{finding.file}:#{finding.line}"
    puts "  #{finding.message}" if finding.message
    explanation = Scryer::FixRunner.explain(finding.suggested_fix)
    puts "  Fix: #{explanation}" unless explanation.empty?
    after = Scryer::FixVerifier.extract_after_snippet(finding.suggested_fix)
    return unless after

    puts "  AFTER:"
    after.each_line { |line| puts "    #{line.chomp}" }
  end

  def print_fix_verification(regressed, total:)
    if regressed.empty?
      puts paint("Verified: all #{total} applied fix(es) confirmed clean on a full re-scan.", :green, :bold)
    else
      puts paint("Warning: #{regressed.size} of #{total} applied fix(es) still show up on a full " \
           "re-scan (an edit may have shifted another finding onto the same rule, or a " \
           "duplicate finding existed elsewhere) — review these by hand:", :yellow)
      regressed.each { |f| puts "  #{f.rule_id} — #{f.file}:#{f.line}" }
    end
  end

  def print_candidate_list(candidates)
    puts ""
    candidates.each_with_index { |f, i| puts "  #{i + 1}) #{f.rule_id} — #{f.file}:#{f.line} — #{f.message}" }
    puts ""
  end

  # Same mapping as Scryer::CLI#select_by_number (see that method's comment)
  # — SCRYER_FIX_NUMBERS is this task's equivalent of the CLI's --number.
  # Aborts (this file's usual bad-input response, matching e.g. apply_baseline
  # above) rather than fixing anything other than what was asked for.
  def select_by_number(candidates, numbers)
    indices = numbers.map do |n|
      i = Integer(n, exception: false)
      abort("Scryer: SCRYER_FIX_NUMBERS value #{n.inspect} isn't a valid position — set " \
            "SCRYER_FIX_LIST=1 to see the numbered candidates first.") unless i
      abort("Scryer: SCRYER_FIX_NUMBERS position #{i} is out of range — only #{candidates.size} " \
            "matching finding(s) (set SCRYER_FIX_LIST=1 to list them).") unless i.between?(1, candidates.size)

      i
    end
    indices.uniq.sort.map { |i| candidates[i - 1] }
  end

  # Same gate as Scryer::CLI#gate_frozen_string_literal — see that method's
  # comment. `explicit` is true when the rake task's rule_id bracket arg
  # was given (e.g. `scryer:fix[frozen_string_literal]`), which is already
  # informed consent for that rule.
  def gate_frozen_string_literal(candidates, explicit:)
    return candidates if explicit

    opted_in, rest = candidates.partition { |f| Scryer::MechanicalFixer.opt_in?(f.rule_id) }
    return candidates if opted_in.empty?

    if $stdin.respond_to?(:tty?) && $stdin.tty?
      print "#{opted_in.size} frozen_string_literal finding(s) matched — this only adds the " \
            "magic comment to #{opted_in.size} file(s) (skipped automatically wherever an " \
            "in-place string mutation makes it unsafe). Include them in this run? [y/N] "
      $stdout.flush
      answer = $stdin.gets.to_s.strip
      return candidates if answer.downcase.start_with?("y")
    end

    puts "Scryer: excluding #{opted_in.size} frozen_string_literal finding(s) from this run — " \
         "pass it as the rule_id (e.g. rails 'scryer:fix[frozen_string_literal]') to include them " \
         "explicitly."
    rest
  end
end
