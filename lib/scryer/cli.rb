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
    EXTENSION_FORMATS = { ".json" => "json", ".html" => "html", ".htm" => "html", ".csv" => "csv", ".sarif" => "sarif" }.freeze

    def initialize(argv, stdout: $stdout, stderr: $stderr)
      @argv = argv
      @stdout = stdout
      @stderr = stderr
    end

    # Returns a process exit code: 0 if clean, 1 if security findings were
    # found (so `scryer -o report.json` can gate CI the way `brakeman -o
    # report.json` does), 2 on a usage error.
    def run
      # `scryer verify` is a distinct subcommand, not a flag on the normal
      # scan — it takes its own small option set (--rule/--file/--path) that
      # would collide with the main parser's -p/-o meanings, so it's
      # dispatched before the main OptionParser ever sees the rest of argv.
      return run_verify(@argv[1..]) if @argv.first == "verify"
      return run_fix(@argv[1..]) if @argv.first == "fix"

      options = parse(@argv)
      return 0 if options[:exit_early]

      # The standalone executable has no equivalent of a Rails app's
      # config/initializers/scryer.rb getting autoloaded at boot — this is
      # the only way to run Scryer.configure (set c.ai_client, c.skip_rules,
      # c.dirs, ...) before a scan starts outside Rails.
      Array(options[:require]).each { |path| require File.expand_path(path) }

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
        dependency_findings = DependencyAudit.insecure_sources(root) + DependencyAudit.vulnerable_gems(root) +
                               DependencyAudit.ruby_eol_check(root) + DependencyAudit.credentials_exposure_check(root)
      end

      return save_baseline(options[:save_baseline], result, dependency_findings) if options[:save_baseline]

      fixed_count = 0
      if options[:baseline]
        dependency_findings, fixed_count = apply_baseline(options[:baseline], result, dependency_findings)
      end

      if Scryer.configuration.ai_client
        @stdout.puts "Scryer: rewriting suggested fixes via the configured AI client..."
        AiFixSuggester.enhance_result!(result, root: root)
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

      print_summary(result: result, dependency_findings: dependency_findings, ran_deps: ran_deps, outputs: outputs,
                    renderer: renderer, fixed_count: fixed_count, baseline_path: options[:baseline])

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
      ruby_eol = DependencyAudit.ruby_eol_check(root)
      credentials_exposure = DependencyAudit.credentials_exposure_check(root)

      (insecure + vulnerable + ruby_eol + credentials_exposure).each do |f|
        @stdout.puts "[#{f.severity.upcase}] #{dependency_label(f)}"
        @stdout.puts "  fix: #{f.suggested_fix}"
      end

      total = insecure.size + vulnerable.size + ruby_eol.size + credentials_exposure.size
      @stdout.puts "\nScryer: #{total} dependency finding(s) (#{insecure.size} insecure source, " \
                   "#{vulnerable.size} vulnerable gem, #{ruby_eol.size} Ruby EOL, " \
                   "#{credentials_exposure.size} credentials exposure)."
      total.positive? ? 1 : 0
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
    def print_summary(result:, dependency_findings:, ran_deps:, outputs:, renderer:, fixed_count: 0, baseline_path: nil)
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
      @stdout.puts ""
      @stdout.puts "Scryer Audit — #{result.files_scanned} files scanned"
      @stdout.puts divider
      @stdout.puts ""
      if baseline_path
        @stdout.puts "Baseline: #{baseline_path} — showing new findings only " \
                     "(#{fixed_count} fixed since baseline)."
        @stdout.puts ""
      end
      clean_rate = renderer.rules_clean_rate
      @stdout.puts "Security Score: #{score["score"]}/100 (#{score["grade"]})"
      @stdout.puts "Checks: #{clean_rate["clean"]}/#{clean_rate["total"]} rules clean (#{clean_rate["percent"]}%)"
      @stdout.puts ""
      rows.each { |label, count| @stdout.puts summary_row(label, count) }
      @stdout.puts divider
      @stdout.puts summary_row("Total", total)
      @stdout.puts ""
      print_top_priorities(renderer.top_risks)
      print_owasp_coverage(renderer.owasp_coverage)
      outputs.each { |path| @stdout.puts "#{format_for(path).upcase} report: #{path}" }
    end

    def summary_row(label, count)
      value = count.nil? ? "skipped (--no-deps)" : "#{count} finding#{"s" unless count == 1}"
      "#{label.ljust(14)}#{value.rjust(20)}"
    end

    # The categories above are counted separately, but nothing else ranks
    # across them — this is what actually backs "tells you what to fix
    # first" rather than just splitting findings into four buckets. Same
    # data ReportRenderer#top_risks already sorts for the HTML report.
    def print_top_priorities(risks)
      return if risks.empty?

      @stdout.puts "Top priorities:"
      risks.each_with_index do |r, i|
        @stdout.puts "  #{i + 1}. [#{r[:severity]}] #{r[:category]} — #{r[:label]} (#{r[:location]})"
      end
      @stdout.puts ""
    end

    # Byproduct of every security rule carrying an owasp_category — see
    # ReportRenderer#owasp_coverage. Scryer's own best-effort tagging, not an
    # OWASP-audited mapping (documented in full in the README).
    def print_owasp_coverage(coverage)
      return if coverage.empty?

      @stdout.puts "OWASP Top 10 (2021) coverage:"
      coverage.each { |category, count| @stdout.puts "  #{category}: #{count} finding#{"s" unless count == 1}" }
      @stdout.puts ""
    end

    # `scryer verify --rule RULE_ID --file PATH` — re-parses just that one
    # file and re-runs just that one rule against it, independent of a full
    # scan. Meant to run right after applying a fix (by hand or via an LLM)
    # to confirm the specific finding it targeted is actually gone, without
    # waiting on/paying for a full project scan. Deliberately narrower than
    # "did this fix introduce a NEW finding elsewhere" — that's what a normal
    # `scryer` run (or `--baseline`) already answers; this only answers "does
    # the one thing I just tried to fix still fire."
    def run_verify(argv)
      options = {}

      parser = OptionParser.new do |opts|
        opts.banner = "Usage: scryer verify --rule RULE_ID --file PATH [--path ROOT]"
        opts.on("--rule RULE_ID", "The rule_id to re-check (required) — see `scryer verify --list-rules`.") { |v| options[:rule] = v }
        opts.on("--file PATH", "File to re-scan (required) — relative to --path, or absolute.") { |v| options[:file] = v }
        opts.on("--path ROOT", "Project root PATH is relative to (default: current directory).") { |v| options[:root] = v }
        opts.on("--list-rules", "List every known rule_id and exit.") { options[:list_rules] = true }
        opts.on("-h", "--help", "Show this help.") { options[:exit_early] = true; @stdout.puts opts }
      end

      begin
        parser.parse!(argv)
      rescue OptionParser::ParseError => e
        raise UsageError, "#{e.message}\n#{parser}"
      end
      return 0 if options[:exit_early]

      if options[:list_rules]
        RuleSet.all.map(&:rule_id).sort.each { |id| @stdout.puts id }
        return 0
      end

      raise UsageError, "scryer verify needs --rule RULE_ID and --file PATH\n#{parser}" unless options[:rule] && options[:file]

      rule_class = RuleSet.all.find { |r| r.rule_id == options[:rule] }
      unless rule_class
        raise UsageError, "unknown rule_id #{options[:rule].inspect} — run `scryer verify --list-rules` to see valid ids."
      end

      root = File.expand_path(options[:root] || Dir.pwd)
      abs_path = File.expand_path(options[:file], root)
      raise UsageError, "no such file: #{abs_path}" unless File.file?(abs_path)

      rel_path = abs_path.sub(/\A#{Regexp.escape(root)}\/?/, "")
      source = File.read(abs_path)

      sexp = begin
        Ripper.sexp(source)
      rescue StandardError => e
        raise UsageError, "#{rel_path} failed to parse: #{e.message}"
      end
      if sexp.nil?
        raise UsageError, "#{rel_path} could not be parsed (a syntax error, or Ruby syntax newer " \
                           "than this gem's Ruby runtime supports)."
      end

      findings = rule_class.new(file: rel_path, source: source, sexp: sexp).scan

      if findings.empty?
        @stdout.puts "scryer verify: #{options[:rule]} no longer fires on #{rel_path} — fix verified."
        0
      else
        @stdout.puts "scryer verify: #{options[:rule]} still fires on #{rel_path} (#{findings.size} finding(s)):"
        findings.each { |f| @stdout.puts "  line #{f.line}: #{f.message}" }
        1
      end
    end

    # `scryer fix` — the third leg of scan → fix → verify. Scans, asks the
    # configured `ai_client` for a rewrite of every qualifying finding (same
    # AiFixSuggester/FixVerifier machinery `scryer:report` already uses to
    # populate `fix_verified`), and — this is the one command in the whole
    # gem that does this — actually writes a fix to a real file, but ONLY
    # when FixVerifier's in-memory check says that exact rewrite clears the
    # finding. Anything not independently verified this way is left alone
    # and reported as needing manual review, same as it would be in a normal
    # report; this command never writes an unverified guess. Requires an
    # `ai_client` (see -r/--require) — there's no non-AI fallback, since a
    # rule's generic suggested_fix is prose, not a machine-applicable patch.
    def run_fix(argv)
      options = {}

      parser = OptionParser.new do |opts|
        opts.banner = "Usage: scryer fix [--rule RULE_ID] [--file PATH] [--path ROOT] [--dry-run]"
        opts.on("--rule RULE_ID", "Only fix findings for this rule_id (repeatable).") { |v| (options[:rules] ||= []) << v }
        opts.on("--file PATH", "Only fix findings in this file (repeatable) — relative to --path, or absolute.") { |v| (options[:files] ||= []) << v }
        opts.on("--path ROOT", "Project root to scan (default: current directory).") { |v| options[:root] = v }
        opts.on("-r PATH", "--require PATH",
                "Require a Ruby file before scanning (repeatable) — use this to call " \
                "Scryer.configure and set c.ai_client, same as the main scan command.") { |v| (options[:require] ||= []) << v }
        opts.on("--skip RULE_ID", "Skip a rule by rule_id (repeatable), same as the main scan command.") { |v| (options[:skip] ||= []) << v }
        opts.on("--dry-run", "Show what would be fixed without writing anything.") { options[:dry_run] = true }
        opts.on("-h", "--help", "Show this help.") { options[:exit_early] = true; @stdout.puts opts }
      end

      begin
        parser.parse!(argv)
      rescue OptionParser::ParseError => e
        raise UsageError, "#{e.message}\n#{parser}"
      end
      return 0 if options[:exit_early]

      Array(options[:require]).each { |path| require File.expand_path(path) }

      ai_client = Scryer.configuration.ai_client
      unless ai_client
        raise UsageError, "scryer fix needs an ai_client configured (see -r/--require and the " \
                           "README's \"AI-assisted fix suggestions\" section) — a rule's generic " \
                           "suggested_fix is prose, not something this command can apply " \
                           "automatically. Nothing has been changed.\n#{parser}"
      end

      root = File.expand_path(options[:root] || Dir.pwd)
      skip_rules = Scryer.configuration.skip_rules + (options[:skip] || [])
      result = Scanner.new(root: root, dirs: Scryer.configuration.dirs, skip_rules: skip_rules).call

      candidates = (result.security_findings + result.performance_findings + result.style_findings)
      candidates = candidates.select { |f| options[:rules].include?(f.rule_id) } if options[:rules]
      candidates = candidates.select { |f| fix_target_file?(f, options[:files], root) } if options[:files]

      if candidates.empty?
        @stdout.puts "scryer fix: no matching findings to fix."
        return 0
      end

      @stdout.puts "scryer fix: #{candidates.size} candidate finding(s) — asking the configured " \
                   "AI client for a rewrite of each, applying only the ones independently " \
                   "verified to clear the finding#{options[:dry_run] ? " (--dry-run: nothing will actually be written)" : ""}..."

      fixed, skipped = FixRunner.apply(candidates, client: ai_client, root: root, dry_run: options[:dry_run])

      print_fix_summary(fixed: fixed, skipped: skipped, dry_run: options[:dry_run])

      return 0 if options[:dry_run] || skipped.empty?

      verify_applied_fixes(fixed, root: root, skip_rules: skip_rules) if fixed.any?

      skipped.empty? ? 0 : 1
    end

    def print_fix_summary(fixed:, skipped:, dry_run:)
      verb = dry_run ? "Would fix" : "Fixed"
      @stdout.puts ""
      @stdout.puts "#{verb} #{fixed.size} finding(s):"
      fixed.each { |f| @stdout.puts "  #{f.rule_id} — #{f.file}:#{f.line}" }
      @stdout.puts ""

      return if skipped.empty?

      @stdout.puts "#{skipped.size} finding(s) need manual review (fix not independently verified):"
      skipped.each { |f| @stdout.puts "  #{f.rule_id} — #{f.file}:#{f.line}" }
      @stdout.puts ""
    end

    # The "verify" leg: re-scan the whole project after every fix has been
    # written and confirm each one is actually gone — see FixRunner.verify.
    def verify_applied_fixes(fixed, root:, skip_rules:)
      @stdout.puts "Re-scanning to verify every applied fix..."
      regressed = FixRunner.verify(fixed, root: root, dirs: Scryer.configuration.dirs, skip_rules: skip_rules)

      if regressed.empty?
        @stdout.puts "Verified: all #{fixed.size} applied fix(es) confirmed clean on a full re-scan."
      else
        @stdout.puts "Warning: #{regressed.size} of #{fixed.size} applied fix(es) still show up on a full " \
                     "re-scan (an edit may have shifted another finding onto the same rule, or a duplicate " \
                     "finding existed elsewhere) — review these by hand:"
        regressed.each { |f| @stdout.puts "  #{f.rule_id} — #{f.file}:#{f.line}" }
      end
    end

    def fix_target_file?(finding, files, root)
      files.any? do |f|
        abs = File.expand_path(f, root)
        rel = abs.sub(/\A#{Regexp.escape(root)}\/?/, "")
        finding.file == rel || finding.file == f
      end
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

    # `--save-baseline PATH` is a distinct mode, same as --audit-deps/
    # --check-gem: it captures every finding across every category (not
    # just security — a legacy app's existing performance/style debt is
    # just as much "not what I'm here to re-litigate today" as its security
    # debt), writes the fingerprints, and exits without writing the normal
    # -o reports. See Scryer::Baseline for why fingerprints, not file:line.
    def save_baseline(path, result, dependency_findings)
      all_findings = (result.security_findings + result.performance_findings + result.style_findings)
                     .map(&:to_h) + dependency_findings.map(&:to_h)
      Baseline.save(path, all_findings)
      @stdout.puts "Scryer: saved baseline of #{all_findings.size} finding(s) to #{path}."
      0
    end

    # Filters `result`'s finding arrays (mutated in place — Result is a
    # plain Struct, this is the same object the caller already holds) and
    # returns [new_dependency_findings, fixed_count] since dependency_findings
    # is a local array in the caller, not a field this method can mutate by
    # reference the way it can Struct fields.
    # `fixed_count` has to be computed ONCE against the union of every
    # category's current fingerprints, not once per category summed
    # together — Baseline.diff's fixed_count is "baseline fingerprints not
    # present in *this* call's findings," so calling it separately per
    # category and summing would count every other category's
    # still-present findings as "fixed" too (verified: this exact bug
    # produced a nonsensical "762 fixed" on a rescan with zero changes,
    # against a 255-finding baseline — fixed by computing fixed_count from
    # the combined set once, while still filtering "new" per category since
    # that part only checks baseline membership, which is fine to do
    # separately).
    def apply_baseline(path, result, dependency_findings)
      baseline_fingerprints = Baseline.load(path)

      security_hashes = result.security_findings.map(&:to_h)
      performance_hashes = result.performance_findings.map(&:to_h)
      style_hashes = result.style_findings.map(&:to_h)
      dependency_hashes = dependency_findings.map(&:to_h)

      all_current_fingerprints = Baseline.fingerprints(security_hashes + performance_hashes + style_hashes + dependency_hashes)
      fixed_count = (baseline_fingerprints - all_current_fingerprints.to_set).size

      result.security_findings = filter_new(result.security_findings, security_hashes, baseline_fingerprints)
      result.performance_findings = filter_new(result.performance_findings, performance_hashes, baseline_fingerprints)
      result.style_findings = filter_new(result.style_findings, style_hashes, baseline_fingerprints)
      filtered_deps = filter_new(dependency_findings, dependency_hashes, baseline_fingerprints)

      [filtered_deps, fixed_count]
    rescue Baseline::LoadError => e
      raise UsageError, e.message
    end

    def filter_new(objects, hashes, baseline_fingerprints)
      fingerprints = Baseline.fingerprints(hashes)
      objects.each_with_index.reject { |_, i| baseline_fingerprints.include?(fingerprints[i]) }.map(&:first)
    end

    def parse(argv)
      options = { outputs: [] }

      parser = OptionParser.new do |opts|
        opts.banner = "Usage: scryer [options]"
        opts.on("-o PATH", "--output PATH",
                "Write a report to PATH (repeatable). Format is inferred from the " \
                "extension: .json, .html, .csv, or .sarif.") { |v| options[:outputs] << v }
        opts.on("-p PATH", "--path PATH", "Root directory to scan (default: current directory).") { |v| options[:path] = v }
        opts.on("-r PATH", "--require PATH",
                "Require a Ruby file before scanning (repeatable) — the file can call " \
                "Scryer.configure to set c.ai_client, c.skip_rules, c.dirs, etc. This is the " \
                "standalone executable's equivalent of a Rails app's config/initializers/scryer.rb " \
                "getting autoloaded at boot; without it there's no way to configure anything " \
                "outside Rails.") { |v| (options[:require] ||= []) << v }
        opts.on("--audit-deps",
                "Check Gemfile.lock for known-vulnerable gems (via OSV.dev — needs network) and " \
                "insecure git/http sources (offline), instead of running the normal static scan. " \
                "Exits non-zero if anything is found, so this can gate CI the same way " \
                "`bundle-audit check` does.") { options[:audit_deps] = true }
        opts.on("--save-baseline PATH",
                "Run the normal scan, save every finding's fingerprint to PATH, then exit — no " \
                "reports written. A later `scryer --baseline PATH` scan reports only findings " \
                "new since this snapshot, so an app with existing security debt can gate CI on " \
                "new issues without being forced to fix everything on day one.") { |v| options[:save_baseline] = v }
        opts.on("--baseline PATH",
                "Compare this scan against a baseline saved by --save-baseline: every report " \
                "(-o files, console summary, exit code) reflects only findings new since PATH " \
                "was saved. Fingerprints ignore line number (rule + file + offending code), so " \
                "an unrelated edit elsewhere in the file won't make an existing finding look " \
                "new.") { |v| options[:baseline] = v }
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
                when "sarif" then renderer.as_sarif
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
