require "json"
require "time"

module Scryer
  # Turns a Scanner::Result into the exact JSON shape documented in
  # CONTRACT2.md (also the ingest POST body shape) and a self-contained HTML
  # report (inline CSS, no external assets except optionally linking out —
  # here, none at all, so it works offline too). The HTML report is laid out
  # similarly to a Brakeman report: an overview, a summary of counts, the
  # full list of checks that ran, a breakdown of warnings by type, and then
  # every finding in detail.
  class ReportRenderer
    SEVERITY_ORDER = %w[critical warning info].freeze
    SEVERITY_LABELS = { "critical" => "Critical", "warning" => "Warning", "info" => "Info" }.freeze
    CSV_HEADERS = %w[kind identifier severity location message suggested_fix code_snippet url].freeze

    # Tiebreak within the same severity for top_risks — a critical finding
    # is a critical finding regardless of category, but when severity is
    # equal this is the order that best matches "what's actually riskiest":
    # a security hole, then a known-vulnerable dependency, ahead of a
    # performance or style issue at the same nominal severity.
    CATEGORY_RISK_PRIORITY = { "security" => 0, "dependency" => 1, "performance" => 2, "code quality" => 3 }.freeze

    # `dependency_findings` is an optional array of Scryer::DependencyAudit::
    # Finding (insecure_sources + vulnerable_gems) — pass it to fold a
    # bundler-audit-like dependency audit into the same report as the static
    # scan, instead of the audit living in separate `--audit-deps` output.
    # Defaults to empty so existing callers that only run the static scan are
    # unaffected.
    def initialize(result:, project_name:, release_label: nil, git_commit_sha: nil, git_branch: nil,
                   dependency_findings: [], scanned_at: Time.now)
      @result = result
      @project_name = project_name
      @release_label = release_label
      @git_commit_sha = git_commit_sha
      @git_branch = git_branch
      @dependency_findings = dependency_findings
      @scanned_at = scanned_at
    end

    def as_hash
      {
        "project_name" => @project_name,
        "scryer_version" => Scryer::VERSION,
        "ruby_version" => RUBY_VERSION,
        "scanned_at" => @scanned_at.utc.iso8601,
        "release_label" => @release_label,
        "git_commit_sha" => @git_commit_sha,
        "git_branch" => @git_branch,
        "files_scanned" => @result.files_scanned,
        "parse_errors" => @result.parse_errors.map { |pe| { "file" => pe[:file], "error" => pe[:error] } },
        "security_findings" => @result.security_findings.map(&:to_h),
        "performance_findings" => @result.performance_findings.map(&:to_h),
        "style_findings" => @result.style_findings.map(&:to_h),
        "duplicate_groups" => @result.duplicate_groups.map { |g| duplicate_group_hash(g) },
        "dependency_findings" => @dependency_findings.map(&:to_h)
      }
    end

    def as_json
      JSON.pretty_generate(as_hash)
    end

    DEFAULT_TOP_RISKS_LIMIT = 5

    # This is what actually backs "tells you what to fix first" — Scryer's
    # categories (security, dependencies, performance, code quality) each
    # already carry a severity ("critical"/"warning"/"info"), but they're
    # scanned and reported separately; nothing ranks across them. top_risks
    # merges every severity-bearing finding (rule-based + dependency) into
    # one list, sorted by severity first and then by category (a security
    # hole outranks a stylistic one at the same severity) — pure aggregation
    # of data every format already has, no new detection logic. Used by the
    # console summary (CLI + rake) and the top of the HTML report; JSON/CSV/
    # SARIF are consumed by other tools that do their own sorting/filtering,
    # so this stays a display-only convenience rather than a new field there.
    def top_risks(limit: DEFAULT_TOP_RISKS_LIMIT)
      h = as_hash
      entries = []
      h["security_findings"].each { |f| entries << finding_risk_entry("security", f) }
      h["performance_findings"].each { |f| entries << finding_risk_entry("performance", f) }
      h["style_findings"].each { |f| entries << finding_risk_entry("code quality", f) }
      h["dependency_findings"].each { |f| entries << dependency_risk_entry(f) }

      entries.sort_by { |e| [SEVERITY_ORDER.index(e[:severity]) || SEVERITY_ORDER.size, CATEGORY_RISK_PRIORITY[e[:category]] || 99] }
             .first(limit)
    end

    # Flat, one-row-per-finding CSV — security + performance findings plus
    # any dependency findings, in that order — for dropping into a
    # spreadsheet or importing into a ticketing tool. Deliberately excludes
    # duplicate-code groups: they're nested member lists, not a single
    # actionable item, so they don't fit a flat "one row = one thing to
    # fix" table (see as_json for the full nested data). No `csv` stdlib
    # dependency — RFC4180-style quoting is small enough to hand-roll, same
    # reasoning as this gem's other hand-rolled parsers/writers.
    def as_csv
      h = as_hash
      rows = [CSV_HEADERS]
      h["security_findings"].each { |f| rows << static_csv_row(f) }
      h["performance_findings"].each { |f| rows << static_csv_row(f) }
      h["style_findings"].each { |f| rows << static_csv_row(f) }
      h["dependency_findings"].each { |f| rows << dependency_csv_row(f) }

      rows.map { |row| row.map { |field| csv_field(field) }.join(",") }.join("\n")
    end

    SARIF_LEVEL_BY_SEVERITY = { "critical" => "error", "warning" => "warning", "info" => "note" }.freeze

    # SARIF 2.1.0 (docs.oasis-open.org/sarif/sarif/v2.1.0) — the format
    # GitHub Code Scanning (and other CI security dashboards) natively
    # ingest, turning findings into inline PR annotations and Security-tab
    # entries instead of a report file nobody opens. Pure data mapping of
    # what's already in as_hash — no new detection logic, and every finding
    # behaves identically to how it does in the other formats.
    def as_sarif
      JSON.pretty_generate(sarif_hash)
    end

    def as_html
      h = as_hash
      security = h["security_findings"]
      performance = h["performance_findings"]
      style = h["style_findings"]
      all_findings = security + performance + style
      by_severity = all_findings.group_by { |f| f["severity"] }
      duplicate_groups = h["duplicate_groups"]
      dependency_findings = h["dependency_findings"]

      <<~HTML
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <title>Scryer report — #{escape(@project_name)}</title>
          <style>#{CSS}</style>
        </head>
        <body>
          <h1>Scryer report</h1>
          <p class="meta">
            #{escape(@project_name)} &middot; #{escape(h["release_label"] || "no release label")} &middot;
            #{escape(h["scanned_at"])} &middot; #{h["files_scanned"]} files scanned
            #{h["parse_errors"].any? ? "&middot; <span class=\"crit\">#{h["parse_errors"].size} parse error(s)</span>" : ""}
          </p>

          #{render_toc(h)}

          <section id="overview">
            <h2>Overview</h2>
            #{render_overview_table(h)}
          </section>

          <section id="summary">
            <h2>Summary</h2>
            #{render_summary_table(security, performance, style, duplicate_groups, dependency_findings)}
          </section>

          <section id="checks-performed">
            <h2>Checks performed #{expand_collapse_controls("#checks-performed")}</h2>
            #{render_checks_performed}
          </section>

          <section id="warnings-by-type">
            <h2>Warnings by type</h2>
            #{render_warnings_by_type(all_findings)}
          </section>

          <section id="findings">
            <h2>Findings (#{all_findings.size}) #{expand_collapse_controls("#findings")}</h2>

            <div id="top-priorities">
              <h3>Top priorities — fix these first</h3>
              #{render_top_priorities(top_risks)}
            </div>

            #{render_severity_section("critical", by_severity["critical"] || [])}
            #{render_severity_section("warning", by_severity["warning"] || [])}
            #{render_severity_section("info", by_severity["info"] || [])}
          </section>

          <section id="duplicates">
            <h2>Duplicate code groups (#{duplicate_groups.size}) #{expand_collapse_controls("#duplicates")}</h2>
            #{render_duplicate_groups(duplicate_groups)}
          </section>

          <section id="dependency-audit">
            <h2>Dependency audit (#{dependency_findings.size}) #{expand_collapse_controls("#dependency-audit")}</h2>
            #{render_dependency_findings(dependency_findings)}
          </section>

          <section id="errors">
            <h2>Files that couldn't be parsed (#{h["parse_errors"].size})</h2>
            #{render_parse_errors(h["parse_errors"])}
          </section>

          <p class="footer">
            Generated by Scryer v#{h["scryer_version"]} (Ruby #{escape(h["ruby_version"])}) &middot;
            heuristic static analysis, not full data-flow/taint analysis — review every finding in
            its surrounding context before acting on it.
          </p>

          <script>#{JS}</script>
        </body>
        </html>
      HTML
    end

    private

    def render_toc(h)
      <<~HTML
        <nav class="toc">
          <a href="#overview">Overview</a>
          <a href="#summary">Summary</a>
          <a href="#checks-performed">Checks performed</a>
          <a href="#warnings-by-type">Warnings by type</a>
          <a href="#findings">Findings</a>
          <a href="#top-priorities">Top priorities</a>
          <a href="#duplicates">Duplicate code (#{h["duplicate_groups"].size})</a>
          <a href="#dependency-audit">Dependency audit (#{h["dependency_findings"].size})</a>
          <a href="#errors">Parse errors (#{h["parse_errors"].size})</a>
        </nav>
      HTML
    end

    def render_overview_table(h)
      rows = {
        "Project" => h["project_name"],
        "Scanned at" => h["scanned_at"],
        "Release label" => h["release_label"] || "—",
        "Git branch" => h["git_branch"] || "—",
        "Git commit" => h["git_commit_sha"] || "—",
        "Files scanned" => h["files_scanned"],
        "Scryer version" => h["scryer_version"],
        "Ruby version" => h["ruby_version"]
      }

      body = rows.map { |k, v| "<tr><th>#{escape(k)}</th><td>#{escape(v)}</td></tr>" }.join
      "<table class=\"kv\">#{body}</table>"
    end

    def render_summary_table(security, performance, style, duplicate_groups, dependency_findings)
      sec_counts = count_by_severity(security)
      perf_counts = count_by_severity(performance)
      style_counts = count_by_severity(style)
      total_counts = SEVERITY_ORDER.each_with_object({}) { |s, acc| acc[s] = sec_counts[s] + perf_counts[s] + style_counts[s] }

      header = "<tr><th>Category</th>" + SEVERITY_ORDER.map { |s| "<th>#{SEVERITY_LABELS[s]}</th>" }.join + "<th>Total</th></tr>"
      sec_row = summary_row("Security", sec_counts)
      perf_row = summary_row("Performance", perf_counts)
      style_row = summary_row("Style", style_counts)
      total_row = summary_row("Total", total_counts, css_class: "total")
      dup_row = "<tr><th>Duplicate code</th><td colspan=\"#{SEVERITY_ORDER.size}\">—</td><td>#{duplicate_groups.size} group(s)</td></tr>"
      deps_row = "<tr><th>Dependency audit</th><td colspan=\"#{SEVERITY_ORDER.size}\">—</td><td>#{dependency_findings.size} finding(s)</td></tr>"

      "<table class=\"summary\">#{header}#{sec_row}#{perf_row}#{style_row}#{dup_row}#{deps_row}#{total_row}</table>"
    end

    def summary_row(label, counts, css_class: nil)
      cells = SEVERITY_ORDER.map { |s| "<td>#{counts[s]}</td>" }.join
      total = counts.values.sum
      "<tr#{css_class ? " class=\"#{css_class}\"" : ""}><th>#{escape(label)}</th>#{cells}<td>#{total}</td></tr>"
    end

    def count_by_severity(findings)
      SEVERITY_ORDER.each_with_object(Hash.new(0)) { |s, acc| acc[s] = findings.count { |f| f["severity"] == s } }
    end

    def rules_by_category
      Scryer::RuleSet.all.group_by(&:category)
    end

    def rule_titles
      Scryer::RuleSet.all.each_with_object({}) { |r, acc| acc[r.rule_id] = r.title }
    end

    # Collapsed by default, same as render_rule_group — this is reference
    # material (every rule that *can* fire, not what actually did), and with
    # 26 security rules alone, showing all three category tables expanded by
    # default buried the sections a reader actually came for (Findings,
    # Top priorities) under a wall of rows nobody needed to see up front.
    def render_checks_performed
      [
        checks_accordion("checks-security", "Security", rules_by_category["security"] || []),
        checks_accordion("checks-performance", "Performance", rules_by_category["performance"] || []),
        checks_accordion("checks-style", "Style", rules_by_category["style"] || [])
      ].join
    end

    def checks_accordion(anchor, label, rules)
      <<~HTML
        <div class="accordion" id="#{anchor}">
          <button type="button" class="accordion-header">
            <span>#{escape(label)}</span>
            <span class="accordion-meta">#{rules.size} rule#{"s" unless rules.size == 1}<span class="chevron">&#9656;</span></span>
          </button>
          <div class="accordion-body">
            #{checks_table(rules)}
          </div>
        </div>
      HTML
    end

    def checks_table(rules)
      return "<p class=\"muted\">None registered.</p>" if rules.empty?

      rows = rules.sort_by(&:rule_id).map do |rule|
        "<tr><td><code>#{escape(rule.rule_id)}</code></td><td>#{escape(rule.title)}</td>" \
        "<td><span class=\"badge #{rule.default_severity}\">#{rule.default_severity.upcase}</span></td></tr>"
      end.join

      "<table class=\"checks\"><tr><th>Rule ID</th><th>Description</th><th>Default severity</th></tr>#{rows}</table>"
    end

    def render_warnings_by_type(all_findings)
      return "<p class=\"muted\">No findings.</p>" if all_findings.empty?

      titles = rule_titles

      by_rule = all_findings.group_by { |f| f["rule_id"] }
      rows = by_rule.sort_by { |rule_id, findings| [-findings.size, rule_id.to_s] }.map do |rule_id, findings|
        worst = SEVERITY_ORDER.find { |s| findings.any? { |f| f["severity"] == s } }
        anchor = rule_group_anchor(worst, rule_id)
        "<tr><td><a class=\"jump-link\" href=\"##{anchor}\"><code>#{escape(rule_id)}</code></a></td>" \
        "<td>#{escape(titles[rule_id] || rule_id)}</td>" \
        "<td>#{escape(findings.first["category"])}</td>" \
        "<td><span class=\"badge #{worst}\">#{SEVERITY_LABELS[worst]}</span></td>" \
        "<td>#{findings.size}</td></tr>"
      end.join

      "<table class=\"checks\"><tr><th>Rule ID</th><th>Description</th><th>Category</th>" \
      "<th>Highest severity</th><th>Count</th></tr>#{rows}</table>"
    end

    # Anchor id for the accordion group a given (severity, rule_id) pair
    # renders into — used both when rendering the group itself and when
    # linking to it from the "Warnings by type" table. rule_id is always a
    # simple snake_case identifier (see Rule#rule_id across lib/scryer/
    # rules/*), so no extra escaping beyond the id-safe substitution below is
    # needed.
    def rule_group_anchor(severity, rule_id)
      "rule-#{severity}-#{rule_id.to_s.gsub(/[^a-zA-Z0-9_-]/, "-")}"
    end

    def expand_collapse_controls(target_selector)
      "<span class=\"accordion-controls\">" \
      "<button type=\"button\" class=\"expand-all\" data-target=\"#{target_selector}\">Expand all</button>" \
      "<button type=\"button\" class=\"collapse-all\" data-target=\"#{target_selector}\">Collapse all</button>" \
      "</span>"
    end

    def render_parse_errors(parse_errors)
      return "<p class=\"muted\">None.</p>" if parse_errors.empty?

      rows = parse_errors.map do |pe|
        "<tr><td>#{escape(pe["file"])}</td><td>#{escape(pe["error"])}</td></tr>"
      end.join

      "<table class=\"checks\"><tr><th>File</th><th>Error</th></tr>#{rows}</table>"
    end

    def duplicate_group_hash(group)
      {
        "kind" => group.kind,
        "similarity" => group.similarity,
        "members" => group.members.map do |m|
          {
            "file" => m.file,
            "name" => m.name,
            "start_line" => m.start_line,
            "end_line" => m.end_line,
            "source_snippet" => m.source_snippet,
            # Only CacheCallInfo members have a cache_key (the fetch/write's
            # key argument) — nil for method/query duplicate members.
            "cache_key" => m.respond_to?(:cache_key) ? m.cache_key : nil
          }
        end
      }
    end

    def render_severity_section(severity, findings)
      return "" if findings.empty?

      titles = rule_titles
      by_rule = findings.group_by { |f| f["rule_id"] }
      groups = by_rule.sort_by { |rule_id, fs| [-fs.size, rule_id.to_s] }.map do |rule_id, fs|
        render_rule_group(severity, rule_id, titles[rule_id] || rule_id, fs)
      end.join

      "<h3 id=\"sev-#{severity}\">#{severity.capitalize} (#{findings.size})</h3>#{groups}"
    end

    # One accordion per rule within a severity — collapsed by default since a
    # single rule (e.g. n_plus_one_query) can easily produce hundreds of
    # findings, which made the old flat list impractical to scan. This is
    # also the jump target for the "Warnings by type" table's links.
    def render_rule_group(severity, rule_id, title, findings)
      anchor = rule_group_anchor(severity, rule_id)
      rows = findings.map { |f| render_finding(severity, f) }.join

      <<~HTML
        <div class="accordion" id="#{anchor}">
          <button type="button" class="accordion-header">
            <span><span class="badge #{severity}">#{severity.upcase}</span> <code>#{escape(rule_id)}</code> #{escape(title)}</span>
            <span class="accordion-meta">#{findings.size} finding#{"s" unless findings.size == 1}<span class="chevron">&#9656;</span></span>
          </button>
          <div class="accordion-body">
            #{rows}
          </div>
        </div>
      HTML
    end

    def render_finding(severity, f)
      <<~ROW
        <div class="finding #{severity}">
          <div class="finding-head">
            <span class="badge #{severity}">#{severity.upcase}</span>
            <code>#{escape(f["rule_id"])}</code>
            <span class="loc">#{escape(f["file"])}#{f["line"] ? ":#{f["line"]}" : ""}</span>
          </div>
          <p>#{escape(f["message"])}</p>
          #{f["code_snippet"] ? "<pre>#{escape(f["code_snippet"])}</pre>" : ""}
          <div class="fix"><strong>Suggested fix:</strong>#{render_markdown(f["suggested_fix"])}</div>
        </div>
      ROW
    end

    KIND_LABELS = {
      "method_duplicate" => "Method duplicate",
      "query_duplicate" => "Query duplicate",
      "cache_duplicate" => "Cache duplicate"
    }.freeze

    def render_duplicate_groups(groups)
      return "<p class=\"muted\">None detected.</p>" if groups.empty?

      groups.each_with_index.map do |g, index|
        members = g["members"].map do |m|
          key_line = m["cache_key"] ? "<p class=\"loc\">cache key: <code>#{escape(m["cache_key"])}</code></p>" : ""
          "<div class=\"dup-member\"><p class=\"loc\">#{escape(m["file"])} — <code>#{escape(m["name"])}</code> " \
          "(lines #{m["start_line"]}&ndash;#{m["end_line"]})</p>#{key_line}<pre>#{escape(m["source_snippet"].to_s)}</pre></div>"
        end.join

        first_member = g["members"].first || {}
        summary = "#{escape(first_member["file"].to_s)}#{g["members"].size > 1 ? " + #{g["members"].size - 1} more" : ""}"

        <<~HTML
          <div class="accordion dup-group" id="dup-group-#{index}">
            <button type="button" class="accordion-header">
              <span><span class="badge kind">#{escape(KIND_LABELS.fetch(g["kind"], g["kind"]))}</span>
              <strong>#{(g["similarity"] * 100).round}% similar</strong> &middot; #{summary}</span>
              <span class="accordion-meta">#{g["members"].size} occurrences<span class="chevron">&#9656;</span></span>
            </button>
            <div class="accordion-body">#{members}</div>
          </div>
        HTML
      end.join
    end

    # dependency_findings entries are Scryer::DependencyAudit::Finding#to_h
    # shapes (kind/gem_name/installed_version/advisory_id/title/url/
    # patched_versions/message/suggested_fix) — a different shape from the
    # rule-based Finding hashes rendered by render_finding, so this has its
    # own layout rather than reusing render_severity_section.
    def render_dependency_findings(dependency_findings)
      return "<p class=\"muted\">None detected (run with dependency auditing enabled to check " \
             "Gemfile.lock against OSV.dev and for insecure git/http sources).</p>" if dependency_findings.empty?

      sorted = dependency_findings.sort_by { |f| [SEVERITY_ORDER.index(f["severity"]) || 99, f["gem_name"].to_s] }
      rows = sorted.map { |f| render_dependency_finding(f) }.join

      "<div class=\"dep-list\">#{rows}</div>"
    end

    def render_dependency_finding(f)
      severity = f["severity"]
      heading = f["kind"] == "insecure_source" ? "Insecure gem source" : "#{escape(f["gem_name"])} #{escape(f["installed_version"])}"
      advisory_text = [f["advisory_id"], f["title"]].compact.map { |t| escape(t) }.join(" — ")
      advisory = advisory_text.empty? ? "" : "<span class=\"loc\">#{advisory_text}</span>"
      link = f["url"] ? " &middot; <a href=\"#{escape(f["url"])}\" target=\"_blank\" rel=\"noopener\">advisory</a>" : ""
      patched = Array(f["patched_versions"])

      <<~ROW
        <div class="finding #{severity}">
          <div class="finding-head">
            <span class="badge #{severity}">#{severity.upcase}</span>
            <strong>#{heading}</strong>
            #{advisory}#{link}
          </div>
          <p>#{escape(f["message"])}</p>
          #{patched.empty? ? "" : "<p class=\"loc\">Patched version(s): #{escape(patched.join(", "))}</p>"}
          <div class="fix"><strong>Suggested fix:</strong>#{render_markdown(f["suggested_fix"])}</div>
        </div>
      ROW
    end

    def render_top_priorities(risks)
      return "<p class=\"muted\">Nothing critical or above — the highest-priority findings, " \
             "if any, are in the sections below.</p>" if risks.empty?

      items = risks.map do |r|
        <<~ITEM
          <li class="finding #{r[:severity]}">
            <div class="finding-head">
              <span class="badge #{r[:severity]}">#{r[:severity].upcase}</span>
              <span class="loc">#{escape(r[:category])} &middot; <code>#{escape(r[:label].to_s)}</code> &middot; #{escape(r[:location].to_s)}</span>
            </div>
            <p>#{escape(r[:message])}</p>
          </li>
        ITEM
      end.join

      "<ol class=\"top-risks\">#{items}</ol>"
    end

    def finding_risk_entry(category, f)
      {
        severity: f["severity"],
        category: category,
        label: f["rule_id"],
        location: f["line"] ? "#{f["file"]}:#{f["line"]}" : f["file"],
        message: f["message"]
      }
    end

    def dependency_risk_entry(f)
      location =
        if f["gem_name"]
          f["installed_version"] ? "#{f["gem_name"]} #{f["installed_version"]}" : f["gem_name"]
        else
          "Gemfile.lock"
        end

      {
        severity: f["severity"],
        category: "dependency",
        label: f["kind"],
        location: location,
        message: f["message"]
      }
    end

    def escape(text)
      text.to_s.gsub("&", "&amp;").gsub("<", "&lt;").gsub(">", "&gt;")
    end

    CODE_FENCE = /```\w*\n?(.*?)```/m
    BOLD = /\*\*(.+?)\*\*/
    INLINE_CODE = /`([^`]+?)`/

    # Suggested-fix text is always human-written prose, whether it came from
    # a rule's static template (occasional inline `code`) or an LLM rewrite
    # (often full Markdown: **bold**, ```fenced code```, paragraphs) — see
    # AiFixSuggester's prompts, which explicitly ask for a
    # "before/after code example". Rendering it as one plain escaped string
    # left literal ** and ``` visible in the HTML report instead of actual
    # formatting. This renders the handful of constructs those two sources
    # actually produce; anything unrecognized just passes through as escaped
    # text, same as before.
    #
    # Every code path here escapes raw text *before* adding any HTML tags of
    # its own, so nothing in `text` (however untrusted — this may be verbatim
    # LLM output) can inject markup; the only unescaped HTML is the literal
    # tag strings this method writes itself.
    def render_markdown(text)
      return "" if text.nil?

      html = +""
      pos = 0
      text.to_s.scan(CODE_FENCE) do
        match = Regexp.last_match
        html << render_prose(text[pos...match.begin(0)])
        html << "<pre>#{escape(match[1].strip)}</pre>"
        pos = match.end(0)
      end
      html << render_prose(text[pos..])
      html
    end

    def render_prose(text)
      return "" if text.nil? || text.strip.empty?

      text.strip.split(/\n{2,}/).map do |paragraph|
        formatted = escape(paragraph.strip).gsub(BOLD, '<strong>\1</strong>').gsub(INLINE_CODE, '<code>\1</code>')
        "<p>#{formatted.gsub("\n", "<br>")}</p>"
      end.join
    end

    def static_csv_row(f)
      [
        f["category"], f["rule_id"], f["severity"],
        "#{f["file"]}#{f["line"] ? ":#{f["line"]}" : ""}",
        f["message"], f["suggested_fix"], f["code_snippet"], nil
      ]
    end

    def dependency_csv_row(f)
      identifier =
        if f["kind"] == "insecure_source"
          "insecure_source"
        elsif f["advisory_id"]
          "#{f["gem_name"]} #{f["installed_version"]} (#{f["advisory_id"]})"
        else
          "#{f["gem_name"]} #{f["installed_version"]}"
        end
      [f["kind"], identifier, f["severity"], "Gemfile.lock", f["message"], f["suggested_fix"], nil, f["url"]]
    end

    def csv_field(value)
      s = value.to_s
      s.match?(/[",\n\r]/) ? "\"#{s.gsub('"', '""')}\"" : s
    end

    # kind/title/severity for the three DependencyAudit finding kinds, which
    # (unlike security/performance/style findings) aren't backed by a
    # Scryer::Rule — described here just so SARIF's tool.driver.rules[]
    # taxonomy has an entry for them too.
    DEPENDENCY_SARIF_RULES = [
      { "id" => "vulnerable_dependency", "title" => "Known-vulnerable gem version (OSV.dev)", "severity" => "critical" },
      { "id" => "insecure_source", "title" => "Insecure (unencrypted) Gemfile.lock source", "severity" => "warning" },
      { "id" => "ruby_eol", "title" => "Ruby version is end-of-life", "severity" => "critical" },
      { "id" => "credentials_exposure", "title" => "config/master.key present and not gitignored", "severity" => "critical" }
    ].freeze

    def sarif_hash
      h = as_hash
      findings = h["security_findings"] + h["performance_findings"] + h["style_findings"]

      {
        "$schema" => "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version" => "2.1.0",
        "runs" => [
          {
            "tool" => {
              "driver" => {
                "name" => "Scryer",
                "version" => Scryer::VERSION,
                "informationUri" => "https://ramlaxmanyadav.github.io/scryer/",
                "rules" => sarif_rules
              }
            },
            "results" => findings.map { |f| sarif_result(f) } + h["dependency_findings"].map { |f| sarif_dependency_result(f) }
          }
        ]
      }
    end

    def sarif_rules
      rule_entries = Scryer::RuleSet.all.map do |rule|
        {
          "id" => rule.rule_id,
          "name" => rule.rule_id,
          "shortDescription" => { "text" => rule.title },
          "defaultConfiguration" => { "level" => SARIF_LEVEL_BY_SEVERITY[rule.default_severity] || "warning" }
        }
      end

      dependency_entries = DEPENDENCY_SARIF_RULES.map do |r|
        {
          "id" => r["id"],
          "name" => r["id"],
          "shortDescription" => { "text" => r["title"] },
          "defaultConfiguration" => { "level" => SARIF_LEVEL_BY_SEVERITY[r["severity"]] || "warning" }
        }
      end

      rule_entries + dependency_entries
    end

    def sarif_result(f)
      physical_location = { "artifactLocation" => { "uri" => f["file"] } }
      physical_location["region"] = { "startLine" => f["line"] } if f["line"]

      {
        "ruleId" => f["rule_id"],
        "level" => SARIF_LEVEL_BY_SEVERITY[f["severity"]] || "warning",
        "message" => { "text" => f["message"] },
        "locations" => [{ "physicalLocation" => physical_location }]
      }
    end

    # Dependency findings don't point at a line in app source — Gemfile.lock
    # itself is the meaningful "location" (no region: nothing to underline
    # inside it the way a code finding underlines a specific line).
    def sarif_dependency_result(f)
      {
        "ruleId" => f["kind"],
        "level" => SARIF_LEVEL_BY_SEVERITY[f["severity"]] || "warning",
        "message" => { "text" => f["message"] },
        "locations" => [{ "physicalLocation" => { "artifactLocation" => { "uri" => "Gemfile.lock" } } }]
      }
    end

    CSS = <<~CSS
      body { font-family: -apple-system, Helvetica, Arial, sans-serif; margin: 2rem; color: #1e293b; }
      h1 { margin-bottom: 0.25rem; }
      h2 { margin-top: 2rem; border-bottom: 1px solid #e2e8f0; padding-bottom: 0.35rem; }
      .meta { color: #64748b; font-size: 0.875rem; margin-top: 0; }
      .crit { color: #b91c1c; font-weight: 600; }
      .toc { display: flex; flex-wrap: wrap; gap: 0.5rem 1rem; background: #f8fafc; border: 1px solid #e2e8f0;
             border-radius: 8px; padding: 0.75rem 1rem; font-size: 0.85rem; }
      .toc a { color: #3730a3; text-decoration: none; }
      .toc a:hover { text-decoration: underline; }
      table.kv, table.summary, table.checks { border-collapse: collapse; width: 100%; font-size: 0.875rem; margin-top: 0.5rem; }
      table.kv th, table.kv td, table.summary th, table.summary td, table.checks th, table.checks td {
        border: 1px solid #e2e8f0; padding: 0.4rem 0.65rem; text-align: left;
      }
      table.kv th { width: 12rem; background: #f8fafc; color: #475569; font-weight: 600; }
      table.summary th, table.checks th { background: #f8fafc; color: #475569; }
      table.summary tr.total { font-weight: 700; }
      #top-priorities { margin-bottom: 1.5rem; padding-bottom: 1rem; border-bottom: 2px solid #e2e8f0; }
      .top-risks { list-style: none; padding: 0; margin: 0; }
      .finding { border: 1px solid #e2e8f0; border-radius: 8px; padding: 0.75rem 1rem; margin-bottom: 0.75rem; }
      .finding-head { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem; }
      .badge { font-size: 0.7rem; font-weight: 700; padding: 0.15rem 0.5rem; border-radius: 4px; }
      .badge.critical { background: #fee2e2; color: #991b1b; }
      .badge.warning { background: #fef3c7; color: #92400e; }
      .badge.info { background: #f1f5f9; color: #475569; }
      .badge.kind { background: #ede9fe; color: #5b21b6; }
      .loc { color: #64748b; font-size: 0.8rem; }
      pre { background: #0f172a; color: #e2e8f0; padding: 0.5rem 0.75rem; border-radius: 6px; overflow-x: auto; font-size: 0.8rem; }
      code { background: #e2e8f0; color: #334155; padding: 0.1rem 0.35rem; border-radius: 4px; font-size: 0.85em; }
      .fix { background: #eef2ff; border-radius: 6px; padding: 0.5rem 0.75rem; font-size: 0.875rem; }
      .fix > strong { display: block; margin-bottom: 0.35rem; }
      .fix p { margin: 0 0 0.5rem; }
      .fix p:last-child { margin-bottom: 0; }
      .fix pre { margin: 0.5rem 0 0; }
      .fix pre:last-child { margin-bottom: 0; }
      .dup-member { margin-top: 0.5rem; }
      .dup-member:first-child { margin-top: 0; }
      .muted { color: #94a3b8; }
      .footer { margin-top: 2.5rem; color: #94a3b8; font-size: 0.8rem; border-top: 1px solid #e2e8f0; padding-top: 0.75rem; }

      .accordion-controls { float: right; font-weight: 400; }
      .accordion-controls button { font: inherit; font-size: 0.75rem; margin-left: 0.5rem; padding: 0.2rem 0.6rem;
        border: 1px solid #cbd5e1; border-radius: 6px; background: #fff; cursor: pointer; color: #334155; }
      .accordion-controls button:hover { background: #f1f5f9; }
      .accordion { border: 1px solid #e2e8f0; border-radius: 8px; margin-bottom: 0.75rem; overflow: hidden; }
      .accordion-header { all: unset; box-sizing: border-box; display: flex; width: 100%; align-items: center;
        justify-content: space-between; gap: 1rem; background: #f8fafc; padding: 0.6rem 1rem; cursor: pointer; }
      .accordion-header:hover { background: #f1f5f9; }
      .accordion-meta { display: flex; align-items: center; gap: 0.5rem; color: #64748b; font-size: 0.8rem; white-space: nowrap; }
      .chevron { display: inline-block; transition: transform 0.15s ease; }
      .accordion.open > .accordion-header .chevron { transform: rotate(90deg); }
      .accordion-body { display: none; padding: 0.75rem 1rem; }
      .accordion.open > .accordion-body { display: block; }
      .accordion .finding, .accordion .dup-member { margin-bottom: 0.75rem; }
      .accordion .finding:last-child, .accordion .dup-member:last-child { margin-bottom: 0; }
      .accordion:target, .accordion.open:target { outline: 2px solid #6366f1; outline-offset: 2px; }
      a.jump-link { color: inherit; text-decoration: none; }
      a.jump-link:hover code { text-decoration: underline; }
    CSS

    JS = <<~JS
      (function () {
        function setOpen(acc, open) {
          if (!acc) return;
          acc.classList.toggle("open", open);
        }

        document.addEventListener("click", function (e) {
          var header = e.target.closest(".accordion-header");
          if (header) {
            var acc = header.closest(".accordion");
            setOpen(acc, !acc.classList.contains("open"));
            return;
          }

          var expandBtn = e.target.closest(".expand-all");
          if (expandBtn) {
            document.querySelectorAll(expandBtn.dataset.target + " .accordion").forEach(function (acc) {
              setOpen(acc, true);
            });
            return;
          }

          var collapseBtn = e.target.closest(".collapse-all");
          if (collapseBtn) {
            document.querySelectorAll(collapseBtn.dataset.target + " .accordion").forEach(function (acc) {
              setOpen(acc, false);
            });
          }
        });

        function openHashTarget() {
          if (!location.hash) return;
          var el;
          try {
            el = document.querySelector(location.hash);
          } catch (err) {
            return;
          }
          if (!el) return;
          var acc = el.classList.contains("accordion") ? el : el.closest(".accordion");
          setOpen(acc, true);
          el.scrollIntoView();
        }

        window.addEventListener("hashchange", openHashTarget);
        openHashTarget();
      })();
    JS
  end
end
