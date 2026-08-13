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
       "rails 'scryer:report[html,nodeps]', rails 'scryer:report[csv]', rails 'scryer:report[sarif]'"
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

    if Scryer.configuration.ai_client
      puts "Scryer: rewriting suggested fixes via the configured AI client..."
      Scryer::AiFixSuggester.enhance_result!(result)
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

    ScryerTasks.print_summary(result: result, dependency_findings: dependency_findings, ran_deps: run_deps, paths: paths, renderer: renderer)

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

  # The "one audit command" summary — a single scan's worth of every
  # category Scryer covers (security, performance, duplicate/smelly code,
  # dependencies), the same categories usually split across RuboCop +
  # Brakeman + bundler-audit + Reek, side by side in one box.
  def print_summary(result:, dependency_findings:, ran_deps:, paths:, renderer:)
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
    puts ""
    puts "Scryer Audit — #{result.files_scanned} files scanned"
    puts divider
    puts ""
    rows.each { |label, count| puts summary_row(label, count) }
    puts divider
    puts summary_row("Total", total)
    puts ""
    print_top_priorities(renderer.top_risks)
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
end
