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

    def initialize(argv, stdout: $stdout, stderr: $stderr, stdin: $stdin)
      @argv = argv
      @stdout = stdout
      @stderr = stderr
      @stdin = stdin
      @color_override = nil
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

      root = File.expand_path(options[:path] || Dir.pwd)

      # The standalone executable has no equivalent of a Rails app's
      # config/initializers/scryer.rb getting autoloaded at boot — this is
      # the only way to run Scryer.configure (set c.ai_client, c.skip_rules,
      # c.dirs, ...) before a scan starts outside Rails. With no explicit
      # `-r`, fall back to auto-requiring config/initializers/scryer.rb
      # under `root`, if it exists — see #auto_discover_initializer.
      require_paths = Array(options[:require])
      require_paths = auto_discover_initializer(root) if require_paths.empty?
      require_paths.each { |path| require File.expand_path(path) }

      return check_gem(options[:check_gem]) if options[:check_gem]

      return audit_deps(root) if options[:audit_deps]

      skip_rules = Scryer.configuration.skip_rules + (options[:skip] || [])
      @stdout.puts "Scryer: skipping #{skip_rules.join(', ')}." if skip_rules.any?
      detect_duplicates = options[:no_duplicates] ? false : Scryer.configuration.detect_duplicates

      result = Scanner.new(root: root, dirs: Scryer.configuration.dirs, skip_rules: skip_rules, detect_duplicates: detect_duplicates).call

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

    # Only consulted when `-r`/`--require` wasn't passed at all — an explicit
    # `-r` (even to a file that doesn't exist, which `require` will raise on)
    # always wins and this is never consulted. config/initializers/scryer.rb
    # is exactly where a Rails app's own boot process would autoload
    # Scryer.configure from (see the generator template at
    # lib/generators/scryer/templates/scryer_initializer.rb); this just saves
    # having to pass `-r config/initializers/scryer.rb` by hand every time
    # when running the standalone executable against a Rails project that
    # already has one. Prints a one-line notice so this is never a silent
    # behavior switch — the whole point is to avoid the "AI client configured
    # but scryer fix isn't using it" confusion an unnoticed missing `-r` used
    # to cause.
    def auto_discover_initializer(root)
      candidate = File.join(root, "config", "initializers", "scryer.rb")
      return [] unless File.file?(candidate)

      @stdout.puts "Scryer: no -r/--require given — found and requiring #{candidate} (pass -r to override)."
      [candidate]
    end

    # Thin wrappers around Scryer::Colorizer bound to this CLI's own stdout
    # and --color/--no-color override — every color call in this file goes
    # through these three instead of calling Colorizer directly.
    def paint(text, *styles)
      Colorizer.paint(text, *styles, stream: @stdout, override: @color_override)
    end

    def paint_severity(text, severity)
      Colorizer.severity(text, severity, stream: @stdout, override: @color_override)
    end

    def paint_grade(text, letter)
      Colorizer.grade(text, letter, stream: @stdout, override: @color_override)
    end

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
        @stdout.puts "[#{paint_severity(f.severity.upcase, f.severity)}] #{dependency_label(f)}"
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

      divider = paint("─" * 32, :gray)
      score = renderer.security_score
      @stdout.puts ""
      @stdout.puts paint("Scryer Audit — #{result.files_scanned} files scanned", :bold)
      @stdout.puts divider
      @stdout.puts ""
      if baseline_path
        @stdout.puts "Baseline: #{baseline_path} — showing new findings only " \
                     "(#{fixed_count} fixed since baseline)."
        @stdout.puts ""
      end
      clean_rate = renderer.rules_clean_rate
      @stdout.puts "Security Score: #{score["score"]}/100 (#{paint_grade(score["grade"], score["grade"])})"
      @stdout.puts "Checks: #{clean_rate["clean"]}/#{clean_rate["total"]} rules clean (#{clean_rate["percent"]}%)"
      @stdout.puts ""
      rows.each { |label, count| @stdout.puts summary_row(label, count) }
      @stdout.puts divider
      @stdout.puts paint(summary_row("Total", total), :bold)
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

      @stdout.puts paint("Top priorities:", :bold)
      risks.each_with_index do |r, i|
        @stdout.puts "  #{i + 1}. [#{paint_severity(r[:severity], r[:severity])}] #{r[:category]} — #{r[:label]} (#{r[:location]})"
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

    # `scryer verify` — re-checks whether specific findings still fire,
    # independent of writing a full report. `--rule`/`--file` narrow the
    # scope; either or both can be omitted to broaden it:
    #   --rule ID --file PATH  → re-parses just that one file and re-runs
    #                            just that one rule (the original, narrowest
    #                            case — meant to run right after applying a
    #                            fix by hand or reviewing an AI suggestion,
    #                            without waiting on/paying for a full scan)
    #   --file PATH only       → re-parses that one file, runs every rule
    #   --rule ID only         → full project scan, filtered to that rule
    #   neither                → full project scan, every rule, every file
    # Deliberately narrower than "did this change introduce a NEW finding
    # elsewhere" in the --rule+--file case — that's what a normal `scryer`
    # run (or `--baseline`) already answers; only the "neither" case here
    # actually covers the whole project, and even then without a report.
    def run_verify(argv)
      options = {}

      parser = OptionParser.new do |opts|
        opts.banner = "Usage: scryer verify [--rule RULE_ID] [--file PATH] [--path ROOT]"
        opts.on("--rule RULE_ID", "Only re-check this rule_id (omit to check every rule) — see `scryer verify --list-rules`.") { |v| options[:rule] = v }
        opts.on("--file PATH", "Only re-check this file (omit to check the whole project) — relative to --path, or absolute.") { |v| options[:file] = v }
        opts.on("--path ROOT", "Project root PATH is relative to, or that gets checked entirely if --file is omitted (default: current directory).") { |v| options[:root] = v }
        opts.on("--list-rules", "List every known rule_id and exit.") { options[:list_rules] = true }
        opts.on("--color", "Force colored output even when stdout isn't a terminal.") { options[:color] = true }
        opts.on("--no-color", "Disable colored output even at a real terminal.") { options[:color] = false }
        opts.on("-h", "--help", "Show this help.") { options[:exit_early] = true; @stdout.puts opts }
      end

      begin
        parser.parse!(argv)
      rescue OptionParser::ParseError => e
        raise UsageError, "#{e.message}\n#{parser}"
      end
      @color_override = options[:color]
      return 0 if options[:exit_early]

      if options[:list_rules]
        RuleSet.all.map(&:rule_id).sort.each { |id| @stdout.puts id }
        return 0
      end

      rule_class = nil
      if options[:rule]
        rule_class = RuleSet.all.find { |r| r.rule_id == options[:rule] }
        raise UsageError, "unknown rule_id #{options[:rule].inspect} — run `scryer verify --list-rules` to see valid ids." unless rule_class
      end

      root = File.expand_path(options[:root] || Dir.pwd)

      if options[:file]
        verify_file(options[:file], root: root, rule_class: rule_class, rule_id: options[:rule])
      else
        verify_project(root: root, rule_id: options[:rule])
      end
    end

    def verify_file(file, root:, rule_class:, rule_id:)
      abs_path = File.expand_path(file, root)
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

      rule_classes = rule_class ? [rule_class] : RuleSet.all
      findings = rule_classes.flat_map { |rc| rc.new(file: rel_path, source: source, sexp: sexp).scan }

      if findings.empty?
        subject = rule_id ? "#{rule_id} no longer fires on #{rel_path}" : "#{rel_path} is clean — no findings"
        @stdout.puts "scryer verify: #{subject} — #{paint('fix verified', :green, :bold)}."
        0
      else
        subject = rule_id ? "#{rule_id} #{paint('still fires', :red, :bold)} on #{rel_path}" : "#{rel_path} #{paint('still has findings', :red, :bold)}"
        @stdout.puts "scryer verify: #{subject} (#{findings.size} finding(s)):"
        if rule_class
          findings.each { |f| @stdout.puts "  line #{f.line}: #{f.message}" }
        else
          @stdout.puts ""
          print_findings_list(findings)
        end
        1
      end
    end

    def verify_project(root:, rule_id:)
      # detect_duplicates: false — `scryer verify` only ever looks at
      # security/performance/style findings (see below), never
      # duplicate_groups, so there's nothing to gain from running that pass
      # here regardless of Scryer.configuration.detect_duplicates.
      result = Scanner.new(root: root, dirs: Scryer.configuration.dirs, skip_rules: Scryer.configuration.skip_rules, detect_duplicates: false).call
      candidates = result.security_findings + result.performance_findings + result.style_findings
      candidates = candidates.select { |f| f.rule_id == rule_id } if rule_id

      if candidates.empty?
        subject = rule_id ? "#{rule_id} no longer fires anywhere under #{root}" : "#{root} is clean — no findings"
        @stdout.puts "scryer verify: #{subject} — #{paint('fix verified', :green, :bold)}."
        0
      else
        subject = rule_id ? "#{rule_id} #{paint('still fires', :red, :bold)} under #{root}" : "#{paint('still has findings', :red, :bold)} under #{root}"
        @stdout.puts "scryer verify: #{subject} (#{candidates.size} finding(s)):"
        @stdout.puts ""
        print_findings_list(candidates)
        1
      end
    end

    SEVERITY_ORDER = { "critical" => 0, "warning" => 1, "info" => 2 }.freeze

    # Grouped by severity (critical first, matching "Top priorities"), one
    # short line per finding (severity tag + location) followed by the
    # message truncated to a scannable length — full untruncated detail is
    # what a real `scryer` report (JSON/HTML) is for; this is meant to be a
    # quick "what's still failing" glance, not a wall of text.
    def print_findings_list(findings)
      findings.sort_by { |f| SEVERITY_ORDER.fetch(f.severity, 3) }.each do |f|
        @stdout.puts "  [#{paint_severity(f.severity, f.severity)}] #{f.rule_id} — #{f.file}:#{f.line}"
        @stdout.puts "      #{truncate_message(f.message)}"
      end
      @stdout.puts ""
    end

    def truncate_message(text, limit: 100)
      text = text.to_s.strip
      return text if text.length <= limit

      cut = text[0...limit]
      cut = cut[0...(cut.rindex(" ") || limit)]
      "#{cut}…"
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
    # `--deps` switches to a completely separate pipeline for dependency
    # findings instead — see Scryer::DependencyFixer and #run_fix_deps below.
    def run_fix(argv)
      options = {}

      parser = OptionParser.new do |opts|
        opts.banner = "Usage: scryer fix [--rule RULE_ID] [--file PATH] [--number N] [--list] [--path ROOT] [--dry-run]\n" \
                      "       scryer fix --deps [--path ROOT] [--dry-run]"
        opts.on("--rule RULE_ID", "Only fix findings for this rule_id (repeatable).") { |v| (options[:rules] ||= []) << v }
        opts.on("--file PATH", "Only fix findings in this file (repeatable) — relative to --path, or absolute.") { |v| (options[:files] ||= []) << v }
        opts.on("--number N", "Only fix the finding(s) at this position in the numbered candidate " \
                               "list (see --list; repeatable, or comma-separated: --number 1,3). " \
                               "Numbering is stable across runs with the same --rule/--file filters.") do |v|
          (options[:numbers] ||= []).concat(v.split(",").map(&:strip))
        end
        opts.on("--list", "Print the matching findings as a numbered list (after --rule/--file " \
                           "filters) and exit without fixing anything.") { options[:list] = true }
        opts.on("--path ROOT", "Project root to scan (default: current directory).") { |v| options[:root] = v }
        opts.on("-r PATH", "--require PATH",
                "Require a Ruby file before scanning (repeatable) — use this to call " \
                "Scryer.configure and set c.ai_client, same as the main scan command. If " \
                "omitted, config/initializers/scryer.rb under --path is auto-required when it " \
                "exists.") { |v| (options[:require] ||= []) << v }
        opts.on("--skip RULE_ID", "Skip a rule by rule_id (repeatable), same as the main scan command.") { |v| (options[:skip] ||= []) << v }
        opts.on("--dry-run", "Show what would be fixed without writing anything.") { options[:dry_run] = true }
        opts.on("--yes", "Apply every independently-verified fix automatically, skipping the " \
                          "per-finding accept/skip prompt this command otherwise shows in an " \
                          "interactive terminal.") { options[:yes] = true }
        opts.on("--deps", "Fix vulnerable dependencies instead of rule-based findings — runs " \
                           "`bundle update GEM --conservative` for each vulnerable gem " \
                           "(DependencyAudit.vulnerable_gems) that has a published patched " \
                           "version, then re-checks OSV.dev to confirm it cleared. Ignores " \
                           "--rule/--file/--number/--list, which only make sense for rule-based " \
                           "findings; --path/--dry-run/--yes/--color/--no-color still apply.") { options[:deps] = true }
        opts.on("--color", "Force colored output even when stdout isn't a terminal.") { options[:color] = true }
        opts.on("--no-color", "Disable colored output even at a real terminal.") { options[:color] = false }
        opts.on("-h", "--help", "Show this help.") { options[:exit_early] = true; @stdout.puts opts }
      end

      begin
        parser.parse!(argv)
      rescue OptionParser::ParseError => e
        raise UsageError, "#{e.message}\n#{parser}"
      end
      @color_override = options[:color]
      return 0 if options[:exit_early]

      root = File.expand_path(options[:root] || Dir.pwd)

      # No explicit `-r`: fall back to auto-requiring
      # config/initializers/scryer.rb under `root`, if it exists — see
      # #auto_discover_initializer.
      require_paths = Array(options[:require])
      require_paths = auto_discover_initializer(root) if require_paths.empty?
      require_paths.each { |path| require File.expand_path(path) }

      return run_fix_deps(options, root) if options[:deps]

      ai_client = Scryer.configuration.ai_client
      skip_rules = Scryer.configuration.skip_rules + (options[:skip] || [])
      # detect_duplicates: false — `scryer fix` only ever works from
      # security/performance/style findings (see `candidates` below); a
      # duplicate-code group has no rule_id/single-line suggested_fix for
      # FixRunner to act on, so there's nothing to gain from that pass here.
      result = Scanner.new(root: root, dirs: Scryer.configuration.dirs, skip_rules: skip_rules, detect_duplicates: false).call

      candidates = (result.security_findings + result.performance_findings + result.style_findings)
      candidates = candidates.select { |f| options[:rules].include?(f.rule_id) } if options[:rules]
      candidates = candidates.select { |f| fix_target_file?(f, options[:files], root) } if options[:files]
      candidates = candidates.sort_by { |f| [f.file.to_s, f.line || 0] }

      if candidates.empty?
        @stdout.puts "scryer fix: no matching findings to fix."
        return 0
      end

      if options[:list]
        print_candidate_list(candidates)
        return 0
      end

      candidates = gate_frozen_string_literal(candidates, explicit: !options[:rules].nil?)
      if candidates.empty?
        @stdout.puts "scryer fix: no matching findings to fix."
        return 0
      end

      candidates = select_by_number(candidates, options[:numbers]) if options[:numbers]

      # A handful of rules (see Scryer::MechanicalFixer) have exactly one
      # correct, deterministic fix and don't need an ai_client at all — only
      # refuse to run when there's genuinely nothing this invocation could
      # possibly fix: no ai_client configured AND none of the matched
      # findings are mechanically fixable. Anything mechanically fixable
      # still gets fixed even with no ai_client set; anything that needs AI
      # but has none configured is simply left for manual review, same as
      # an AI reply the verifier rejects.
      if ai_client.nil? && candidates.none? { |f| MechanicalFixer.supported?(f.rule_id) }
        raise UsageError, "scryer fix needs an ai_client configured (see -r/--require and the " \
                           "README's \"AI-assisted fix suggestions\" section) — none of the " \
                           "matched finding(s) have a built-in mechanical fixer " \
                           "(#{MechanicalFixer::SUPPORTED_RULES.join(", ")}), and a rule's generic " \
                           "suggested_fix is prose, not something this command can apply " \
                           "automatically on its own. Nothing has been changed.\n#{parser}"
      end

      # In an interactive terminal (and not --dry-run/--yes), review each
      # independently-verified fix one at a time before writing it — "yes /
      # skip / yes to all remaining / cancel" — instead of silently applying
      # everything that verified clean. Non-interactive runs (CI, piped
      # stdin) and --dry-run/--yes keep the old apply-everything-verified
      # behavior, since there's no one to ask.
      confirm = build_fix_confirmer if interactive_terminal? && !options[:dry_run] && !options[:yes]

      @stdout.puts "scryer fix: #{candidates.size} candidate finding(s) — applying built-in fixes " \
                   "where one exists, otherwise asking the configured AI client for a rewrite; " \
                   "either way, only writing what's independently verified to clear the " \
                   "finding#{options[:dry_run] ? " (--dry-run: nothing will actually be written)" : ""}..."

      fixed, skipped = FixRunner.apply(candidates, client: ai_client, root: root, dry_run: options[:dry_run], confirm: confirm) do |finding, status, error|
        print_fix_progress(finding, status, error)
      end

      print_fix_summary(fixed: fixed, skipped: skipped, dry_run: options[:dry_run])

      return 0 if options[:dry_run]

      verify_applied_fixes(fixed, root: root, skip_rules: skip_rules) if fixed.any?

      skipped.empty? ? 0 : 1
    end

    # Printed once per finding, as FixRunner.apply resolves it — not just in
    # the final summary — so a developer watching the run can see what's
    # happening and why, not just a wall of silence until it's all done.
    def print_fix_progress(finding, status, error = nil)
      label = { fixed: "Fixed", would_fix: "Would fix", declined: "Skipped (declined)",
                ai_error: "Skipped (AI client error)", cancelled: "Skipped (cancelled)",
                skipped: "Skipped (needs manual review)" }.fetch(status)
      colored_label = %i[fixed would_fix].include?(status) ? paint(label, :green, :bold) : paint(label, :yellow)
      @stdout.puts "#{colored_label}: #{finding.rule_id} — #{finding.file}:#{finding.line}"

      if status == :ai_error && error
        @stdout.puts "  #{paint("#{error.class}: #{error.message}", :red)}"
      else
        explanation = FixRunner.explain(finding.suggested_fix)
        @stdout.puts "  #{explanation}" unless explanation.empty?
      end
    end

    def print_fix_summary(fixed:, skipped:, dry_run:)
      verb = dry_run ? "Would fix" : "Fixed"
      @stdout.puts ""
      @stdout.puts paint("#{verb} #{fixed.size} finding(s):", :green, :bold)
      fixed.each { |f| @stdout.puts "  #{f.rule_id} — #{f.file}:#{f.line}" }
      @stdout.puts ""

      return if skipped.empty?

      @stdout.puts paint("#{skipped.size} finding(s) not applied (declined, or fix not independently verified):", :yellow)
      skipped.each { |f| @stdout.puts "  #{f.rule_id} — #{f.file}:#{f.line}" }
      @stdout.puts ""
    end

    # `scryer fix --deps` — see Scryer::DependencyFixer for why this is a
    # separate pipeline from the rule-based one above (a DependencyAudit
    # finding has no .line/.file/.rule_id to rewrite). Needs network (OSV.dev)
    # both up front and again for DependencyFixer's own post-update re-check.
    def run_fix_deps(options, root)
      @stdout.puts "scryer fix --deps: querying OSV.dev for known-vulnerable gems (needs network)..."
      findings = DependencyAudit.vulnerable_gems(root)

      if findings.empty?
        @stdout.puts "scryer fix --deps: no vulnerable gems found."
        return 0
      end

      actionable = findings.select { |f| Array(f.patched_versions).any? }
      if actionable.empty?
        @stdout.puts "scryer fix --deps: #{findings.size} vulnerable gem finding(s), but none have " \
                     "a published patched version yet to upgrade to — nothing this command can run. " \
                     "See `scryer --audit-deps` for details."
        return 1
      end

      gem_count = actionable.map(&:gem_name).uniq.size
      @stdout.puts "scryer fix --deps: #{actionable.size} finding(s) across #{gem_count} gem(s) — " \
                   "running `bundle update GEM --conservative` for each" \
                   "#{options[:dry_run] ? " (--dry-run: nothing will actually run)" : ""}..."

      fixed, skipped = DependencyFixer.apply(findings, root: root, dry_run: options[:dry_run]) do |finding, status, error|
        print_deps_fix_progress(finding, status, error)
      end

      print_deps_fix_summary(fixed: fixed, skipped: skipped, dry_run: options[:dry_run])
      return 0 if options[:dry_run]

      skipped.empty? ? 0 : 1
    end

    def print_deps_fix_progress(finding, status, error = nil)
      label = { fixed: "Fixed", would_fix: "Would fix", error: "Error running bundle update",
                skipped: "Skipped (needs manual review)" }.fetch(status)
      colored_label = %i[fixed would_fix].include?(status) ? paint(label, :green, :bold) : paint(label, :yellow)
      @stdout.puts "#{colored_label}: #{finding.gem_name}#{finding.advisory_id ? " (#{finding.advisory_id})" : ""}"

      if error
        @stdout.puts "  #{paint(error.to_s.strip, :red)}"
      elsif status == :skipped && finding.suggested_fix
        @stdout.puts "  #{finding.suggested_fix}"
      end
    end

    def print_deps_fix_summary(fixed:, skipped:, dry_run:)
      verb = dry_run ? "Would fix" : "Fixed"
      @stdout.puts ""
      @stdout.puts paint("#{verb} #{fixed.size} finding(s):", :green, :bold)
      fixed.each { |f| @stdout.puts "  #{f.gem_name}#{f.advisory_id ? " (#{f.advisory_id})" : ""}" }
      @stdout.puts ""

      return if skipped.empty?

      @stdout.puts paint("#{skipped.size} finding(s) not applied (no patched version yet, bundle update " \
                         "failed, or the re-check still shows it vulnerable):", :yellow)
      skipped.each { |f| @stdout.puts "  #{f.gem_name}#{f.advisory_id ? " (#{f.advisory_id})" : ""}" }
      @stdout.puts ""
    end

    # The interactive half of FixRunner.apply's `confirm:` hook — shown once
    # per independently-verified finding, right before it would be written.
    # Numeric choices only (no y/n/a/s letters): "3" (yes to all remaining)
    # latches acceptance for every later call without prompting again;
    # "4" (cancel) returns :cancel, which FixRunner.apply treats as "stop
    # entirely" — every remaining candidate is marked :cancelled without
    # this lambda being called again. Anything other than "1"/"2"/"3"/"4"
    # (including a blank answer) re-prompts rather than guessing.
    def build_fix_confirmer
      mode = :ask
      lambda do |finding|
        next true if mode == :all

        print_finding_preview(finding)
        loop do
          @stdout.puts "Apply this fix?"
          @stdout.puts "  1) Yes"
          @stdout.puts "  2) Skip"
          @stdout.puts "  3) Yes to all remaining"
          @stdout.puts "  4) Cancel (stop reviewing — nothing further will be attempted)"
          @stdout.print "Choice: "
          @stdout.flush
          case @stdin.gets.to_s.strip
          when "1" then break true
          when "2" then break false
          when "3" then mode = :all; break true
          when "4" then break :cancel
          else @stdout.puts "Please enter 1, 2, 3, or 4."
          end
        end
      end
    end

    def print_finding_preview(finding)
      @stdout.puts ""
      @stdout.puts "#{finding.rule_id} — #{finding.file}:#{finding.line}"
      @stdout.puts "  #{finding.message}" if finding.message
      explanation = FixRunner.explain(finding.suggested_fix)
      @stdout.puts "  Fix: #{explanation}" unless explanation.empty?
      after = FixVerifier.extract_after_snippet(finding.suggested_fix)
      return unless after

      @stdout.puts "  AFTER:"
      after.each_line { |line| @stdout.puts "    #{line.chomp}" }
    end

    # frozen_string_literal (see MechanicalFixer::OPT_IN_RULES) is left out
    # of an unscoped `scryer fix` sweep by default — it's a cosmetic,
    # `info`-severity finding that would otherwise touch nearly every file
    # in the project. Explicitly naming it via --rule is already informed
    # consent, so this only gates an unscoped run: in an interactive
    # terminal it asks; non-interactively (CI, piped stdin) it's excluded
    # with a one-line notice, discoverable via `--rule frozen_string_literal`.
    def gate_frozen_string_literal(candidates, explicit:)
      return candidates if explicit

      opted_in, rest = candidates.partition { |f| MechanicalFixer.opt_in?(f.rule_id) }
      return candidates if opted_in.empty?

      if interactive_terminal?
        @stdout.print "#{opted_in.size} frozen_string_literal finding(s) matched — this only adds " \
                      "the magic comment to #{opted_in.size} file(s) (skipped automatically " \
                      "wherever an in-place string mutation makes it unsafe). Include them in " \
                      "this run? [y/N] "
        @stdout.flush
        answer = @stdin.gets.to_s.strip
        return candidates if answer.downcase.start_with?("y")
      end

      @stdout.puts "scryer fix: excluding #{opted_in.size} frozen_string_literal finding(s) from " \
                   "this run — pass --rule frozen_string_literal to include them explicitly."
      rest
    end

    # The "verify" leg: re-scan the whole project after every fix has been
    # written and confirm each one is actually gone — see FixRunner.verify.
    def verify_applied_fixes(fixed, root:, skip_rules:)
      @stdout.puts "Re-scanning to verify every applied fix..."
      regressed = FixRunner.verify(fixed, root: root, dirs: Scryer.configuration.dirs, skip_rules: skip_rules)

      if regressed.empty?
        @stdout.puts paint("Verified: all #{fixed.size} applied fix(es) confirmed clean on a full re-scan.", :green, :bold)
      else
        @stdout.puts paint("Warning: #{regressed.size} of #{fixed.size} applied fix(es) still show up on a full " \
                     "re-scan (an edit may have shifted another finding onto the same rule, or a duplicate " \
                     "finding existed elsewhere) — review these by hand:", :yellow)
        regressed.each { |f| @stdout.puts "  #{f.rule_id} — #{f.file}:#{f.line}" }
      end
    end

    def print_candidate_list(candidates)
      @stdout.puts ""
      candidates.each_with_index { |f, i| @stdout.puts "  #{i + 1}) #{f.rule_id} — #{f.file}:#{f.line} — #{f.message}" }
      @stdout.puts ""
    end

    # Maps 1-based positions in `candidates` (as printed by print_candidate_list)
    # back to the Finding at that position. Raises UsageError (caught by #run,
    # same as every other bad-input case in this command) on a non-integer or
    # out-of-range value — this never silently fixes something other than
    # what was asked for.
    def select_by_number(candidates, numbers)
      indices = numbers.map do |n|
        i = Integer(n, exception: false)
        raise UsageError, "--number #{n.inspect} isn't a valid position — run with --list to see " \
                           "the numbered candidates first." unless i
        raise UsageError, "--number #{i} is out of range — only #{candidates.size} matching " \
                           "finding(s) (see --list)." unless i.between?(1, candidates.size)

        i
      end
      indices.uniq.sort.map { |i| candidates[i - 1] }
    end

    def interactive_terminal?
      @stdin.respond_to?(:tty?) && @stdin.tty?
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
                "getting autoloaded at boot. If omitted, config/initializers/scryer.rb under " \
                "--path is auto-required when it exists.") { |v| (options[:require] ||= []) << v }
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
        opts.on("--no-duplicates",
                "Skip duplicate-code detection (method/query/cache-key similarity across models, " \
                "controllers, helpers, and concerns) for this run only, regardless of " \
                "c.detect_duplicates — doesn't affect other invocations.") { options[:no_duplicates] = true }
        opts.on("--check-gem NAME[:VERSION]",
                "Query OSV.dev for known vulnerabilities affecting a single gem, independent of " \
                "any Gemfile.lock or full scan/audit — instead of running the normal static " \
                "scan. Omit :VERSION to see every advisory ever filed against the gem across " \
                "all versions.") { |v| options[:check_gem] = v }
        opts.on("--project-name NAME", "Project name shown in the report header.") { |v| options[:project_name] = v }
        opts.on("--branch BRANCH", "Git branch label recorded in the report (overrides the actual checked-out branch).") { |v| options[:branch] = v }
        opts.on("--color", "Force colored output even when stdout isn't a terminal (e.g. piped to `less -R`).") { options[:color] = true }
        opts.on("--no-color", "Disable colored output even at a real terminal.") { options[:color] = false }
        opts.on("-v", "--version", "Show the Scryer version.") { options[:exit_early] = true; @stdout.puts Scryer::VERSION }
        opts.on("-h", "--help", "Show this help.") { options[:exit_early] = true; @stdout.puts opts }
      end

      begin
        parser.parse!(argv)
      rescue OptionParser::ParseError => e
        raise UsageError, "#{e.message}\n#{parser}"
      end

      @color_override = options[:color]
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
