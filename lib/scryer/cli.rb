require "optparse"
require "fileutils"
require "shellwords"

module Scryer
  # Backs the `scryer` executable (see exe/scryer) — a standalone,
  # Rails-free way to run a scan, mirroring `brakeman -o report.json`.
  # Deliberately separate from lib/scryer.rb: OptionParser/Shellwords are
  # only needed for this CLI entry point, not when the gem is required
  # inside a host app.
  class CLI
    EXTENSION_FORMATS = { ".json" => "json", ".html" => "html", ".htm" => "html", ".csv" => "csv" }.freeze

    def initialize(argv, stdout: $stdout, stderr: $stderr)
      @argv = argv
      @stdout = stdout
      @stderr = stderr
    end

    # Returns a process exit code: 0 if clean, 1 if security findings were
    # found (so `scryer -o report.json` can gate CI the way `brakeman -o
    # report.json` does), 2 on a usage error.
    def run
      options = parse(@argv)
      return 0 if options[:exit_early]
      return check_gem(options[:check_gem]) if options[:check_gem]

      root = File.expand_path(options[:path] || Dir.pwd)
      return audit_deps(root) if options[:audit_deps]

      skip_rules = Scryer.configuration.skip_rules + (options[:skip] || [])
      @stdout.puts "Scryer: skipping #{skip_rules.join(', ')}." if skip_rules.any?

      result = Scanner.new(root: root, dirs: Scryer.configuration.dirs, skip_rules: skip_rules).call

      # Dependency auditing (OSV.dev) runs by default — a single `scryer`
      # invocation is meant to cover the same ground as RuboCop + Brakeman +
      # bundler-audit + Reek run separately, and that story isn't true if
      # the dependency half is silently skipped unless you remember a flag.
      # `--no-deps` opts back out for a fast, fully offline run (e.g. no
      # network in this environment, or you only want the static scan).
      ran_deps = !options[:no_deps]
      dependency_findings = []
      if ran_deps
        @stdout.puts "Scryer: querying OSV.dev for known-vulnerable gems (needs network)..."
        dependency_findings = DependencyAudit.insecure_sources(root) + DependencyAudit.vulnerable_gems(root)
      end

      if Scryer.configuration.ai_client
        @stdout.puts "Scryer: rewriting suggested fixes via the configured AI client..."
        AiFixSuggester.enhance_result!(result)
        AiFixSuggester.enhance_many!(dependency_findings) unless dependency_findings.empty?
      end

      renderer = ReportRenderer.new(
        result: result,
        project_name: options[:project_name] || File.basename(root),
        release_label: git(root, "describe --tags --always"),
        git_commit_sha: git(root, "rev-parse HEAD"),
        git_branch: options[:branch] || git(root, "rev-parse --abbrev-ref HEAD"),
        dependency_findings: dependency_findings
      )

      outputs = options[:outputs].empty? ? default_outputs(root) : options[:outputs]
      outputs.each { |path| write_report(renderer, path) }

      print_summary(result: result, dependency_findings: dependency_findings, ran_deps: ran_deps, outputs: outputs)

      result.security_findings.empty? && dependency_findings.empty? ? 0 : 1
    rescue UsageError => e
      @stderr.puts "scryer: #{e.message}"
      2
    end

    private

    UsageError = Class.new(StandardError)

    # Mirrors the `scryer:audit_dependencies` rake task's output/exit-code
    # behavior, so `scryer --audit-deps` works the same outside a Rails app.
    def audit_deps(root)
      @stdout.puts "Scryer: checking Gemfile.lock sources (offline)..."
      insecure = DependencyAudit.insecure_sources(root)

      @stdout.puts "Scryer: querying OSV.dev for known vulnerabilities (needs network)..."
      vulnerable = DependencyAudit.vulnerable_gems(root)

      (insecure + vulnerable).each do |f|
        label = f.kind == "insecure_source" ? "[#{f.severity.upcase}] #{f.message}" : "[#{f.severity.upcase}] #{f.gem_name} #{f.installed_version} - #{f.advisory_id}: #{f.title}"
        @stdout.puts label
        @stdout.puts "  fix: #{f.suggested_fix}"
      end

      total = insecure.size + vulnerable.size
      @stdout.puts "\nScryer: #{total} dependency finding(s) (#{insecure.size} insecure source, #{vulnerable.size} vulnerable gem)."
      total.positive? ? 1 : 0
    end

    # The "one audit command" summary — a single scan's worth of every
    # category Scryer covers (security, performance, duplicate/smelly code,
    # dependencies), the same categories usually split across RuboCop +
    # Brakeman + bundler-audit + Reek, side by side in one box.
    def print_summary(result:, dependency_findings:, ran_deps:, outputs:)
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
      @stdout.puts ""
      @stdout.puts "Scryer Audit — #{result.files_scanned} files scanned"
      @stdout.puts divider
      @stdout.puts ""
      rows.each { |label, count| @stdout.puts summary_row(label, count) }
      @stdout.puts divider
      @stdout.puts summary_row("Total", total)
      @stdout.puts ""
      outputs.each { |path| @stdout.puts "#{format_for(path).upcase} report: #{path}" }
    end

    def summary_row(label, count)
      value = count.nil? ? "skipped (--no-deps)" : "#{count} finding#{"s" unless count == 1}"
      "#{label.ljust(14)}#{value.rjust(20)}"
    end

    # One-off OSV.dev lookup for a single gem — no Gemfile.lock, no scan,
    # no other network calls. `spec` is "name" or "name:version" (colon
    # rather than a second CLI arg, so this stays a single -o-style flag).
    def check_gem(spec)
      name, version = spec.split(":", 2)
      label = version ? "#{name} #{version}" : "#{name} (all versions)"

      @stdout.puts "Scryer: querying OSV.dev for #{label}..."
      findings = DependencyAudit.check_gem(name, version)

      findings.each do |f|
        @stdout.puts "[#{f.severity.upcase}] #{f.advisory_id}: #{f.title}"
        @stdout.puts "  fix: #{f.suggested_fix}"
      end

      @stdout.puts "\nScryer: #{findings.size} advisory(-ies) found for #{label}."
      findings.empty? ? 0 : 1
    end

    def parse(argv)
      options = { outputs: [] }

      parser = OptionParser.new do |opts|
        opts.banner = "Usage: scryer [options]"
        opts.on("-o PATH", "--output PATH",
                "Write a report to PATH (repeatable). Format is inferred from the " \
                "extension: .json, .html, or .csv.") { |v| options[:outputs] << v }
        opts.on("-p PATH", "--path PATH", "Root directory to scan (default: current directory).") { |v| options[:path] = v }
        opts.on("--audit-deps",
                "Check Gemfile.lock for known-vulnerable gems (via OSV.dev — needs network) and " \
                "insecure git/http sources (offline), instead of running the normal static scan. " \
                "Exits non-zero if anything is found, so this can gate CI the same way " \
                "`bundle-audit check` does.") { options[:audit_deps] = true }
        opts.on("--no-deps",
                "Skip the dependency audit (OSV.dev vulnerable gems + insecure git/http sources) " \
                "that otherwise runs as part of every normal scan. Use this for a fast, fully " \
                "offline run — e.g. no network available, or you only want the static " \
                "findings.") { options[:no_deps] = true }
        opts.on("--skip RULE_ID",
                "Skip a rule by rule_id (repeatable) — e.g. a known false positive on this " \
                "codebase. Adds to c.skip_rules for this run only; doesn't affect other " \
                "invocations.") { |v| (options[:skip] ||= []) << v }
        opts.on("--check-gem NAME[:VERSION]",
                "Query OSV.dev for known vulnerabilities affecting a single gem, independent of " \
                "any Gemfile.lock or full scan/audit — instead of running the normal static " \
                "scan. Omit :VERSION to see every advisory ever filed against the gem across " \
                "all versions.") { |v| options[:check_gem] = v }
        opts.on("--project-name NAME", "Project name shown in the report header.") { |v| options[:project_name] = v }
        opts.on("--branch BRANCH", "Git branch label recorded in the report (overrides the actual checked-out branch).") { |v| options[:branch] = v }
        opts.on("-v", "--version", "Show the Scryer version.") { options[:exit_early] = true; @stdout.puts Scryer::VERSION }
        opts.on("-h", "--help", "Show this help.") { options[:exit_early] = true; @stdout.puts opts }
      end

      begin
        parser.parse!(argv)
      rescue OptionParser::ParseError => e
        raise UsageError, "#{e.message}\n#{parser}"
      end

      options
    end

    def write_report(renderer, path)
      format = format_for(path)
      content = case format
                when "json" then renderer.as_json
                when "csv" then renderer.as_csv
                else renderer.as_html
                end

      FileUtils.mkdir_p(File.dirname(File.expand_path(path)))
      File.write(path, content)
    end

    def format_for(path)
      ext = File.extname(path).downcase
      EXTENSION_FORMATS[ext] ||
        raise(UsageError, "don't know how to write #{path} — recognized extensions are " \
                           "#{EXTENSION_FORMATS.keys.join(', ')}.")
    end

    def default_outputs(root)
      dir = File.join(root, "tmp")
      [File.join(dir, "scryer_report.json"), File.join(dir, "scryer_report.html")]
    end

    def git(root, cmd)
      output = `git -C #{Shellwords.escape(root)} #{cmd} 2>/dev/null`.strip
      output.empty? ? nil : output
    rescue StandardError
      nil
    end
  end
end
