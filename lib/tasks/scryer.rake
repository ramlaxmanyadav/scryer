require "json"
require "fileutils"

# Deliberately does NOT depend on the Rails `:environment` task — the
# scanning engine itself needs no Rails/bundler to run, so this task works
# equally via `bin/rails scryer:report` inside a Rails app or plain
# `bundle exec rake -f <this file> scryer:report` outside one. Avoids
# ActiveSupport methods (`.presence`/`.blank?`) for the same reason — plain
# Ruby nil-or-empty checks only.
namespace :scryer do
  desc "Run Scryer and write a report. Args are any mix of json/html/csv (which formats " \
       "to write — default json,html), the token 'deps' (fold a dependency audit — OSV.dev " \
       "vulnerable gems + insecure git/http sources, same checks as scryer:audit_dependencies " \
       "— into this report instead of running it separately), plus at most one path (a " \
       "directory when writing more than one format, or an exact file for a single format). " \
       "Rake splits bracket args on every comma, so pass each token as its own item rather " \
       "than one comma-joined string. e.g. rails scryer:report, rails 'scryer:report[html]', " \
       "rails 'scryer:report[json,doc/security.json]', rails 'scryer:report[json,html]', " \
       "rails 'scryer:report[html,deps]', rails 'scryer:report[csv]'"
  task :report, [:format] do |_, args|
    root = defined?(Rails) ? Rails.root.to_s : Dir.pwd
    dirs = Scryer.configuration.dirs

    # Ignore the declared :format name and read every positional value Rake
    # was given (args.to_a) — the whole point is accepting a variable number
    # of format/deps tokens plus one path, which a single named param can't do.
    formats, path_arg, include_deps = parse_report_args(args.to_a)

    skip_rules = Scryer.configuration.skip_rules
    puts "Scryer: skipping #{skip_rules.join(', ')}." if skip_rules.any?

    result = Scryer::Scanner.new(root: root, dirs: dirs, skip_rules: skip_rules).call

    dependency_findings = []
    if include_deps
      puts "Scryer: checking Gemfile.lock sources (offline)..."
      puts "Scryer: querying OSV.dev for known vulnerabilities (needs network)..."
      dependency_findings = Scryer::DependencyAudit.insecure_sources(root) + Scryer::DependencyAudit.vulnerable_gems(root)
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
                else renderer.as_html
                end
      File.write(path, content)
    end

    puts "Scryer: #{result.files_scanned} files scanned, " \
         "#{result.security_findings.size} security findings, " \
         "#{result.performance_findings.size} performance findings, " \
         "#{result.duplicate_groups.size} duplicate groups" \
         "#{include_deps ? ", #{dependency_findings.size} dependency findings" : ""}."
    puts "Report written to #{paths.values.join(', ')}"
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

    (insecure + vulnerable).each do |f|
      label = f.kind == "insecure_source" ? "[#{f.severity.upcase}] #{f.message}" : "[#{f.severity.upcase}] #{f.gem_name} #{f.installed_version} - #{f.advisory_id}: #{f.title}"
      puts label
      puts "  fix: #{f.suggested_fix}"
    end

    total = insecure.size + vulnerable.size
    puts "\nScryer: #{total} dependency finding(s) (#{insecure.size} insecure source, #{vulnerable.size} vulnerable gem)."
    abort("Scryer: dependency audit failed.") if total.positive?
  end

  VALID_FORMATS = %w[json html csv].freeze
  EXTENSION_FOR_FORMAT = { "json" => "json", "html" => "html", "csv" => "csv" }.freeze
  DEPS_TOKEN = "deps".freeze

  # tokens is every bracket arg Rake was given, e.g. %w[json doc/security.json] or
  # %w[json html] or %w[html deps] or []. Returns [formats, path_arg,
  # include_deps] — any token matching a known format is a format, the
  # literal "deps" token opts into folding a dependency audit into the
  # report, and at most one other token is allowed, which is the path.
  def parse_report_args(tokens)
    tokens = tokens.map { |t| blank_to_nil(t) }.compact
    include_deps = tokens.any? { |t| t.downcase == DEPS_TOKEN }
    tokens = tokens.reject { |t| t.downcase == DEPS_TOKEN }

    format_tokens, other_tokens = tokens.partition { |t| VALID_FORMATS.include?(t.downcase) }

    if other_tokens.size > 1
      abort "Scryer: only one path is allowed — got #{other_tokens.join(', ')}."
    end

    formats = format_tokens.map(&:downcase).uniq
    formats = %w[json html] if formats.empty?

    [formats, other_tokens.first, include_deps]
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
end
