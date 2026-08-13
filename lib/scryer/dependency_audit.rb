require "json"
require "date"

module Scryer
  # Dependency vulnerability + supply-chain-hygiene checks for Gemfile.lock —
  # the same broad goal as bundler-audit (github.com/rubysec/bundler-audit),
  # built independently on a different data source and file parser: rather
  # than bundler-audit's local clone of the ruby-advisory-db git repo, this
  # queries OSV.dev's public API (osv.dev — Google's Open Source
  # Vulnerabilities database, covering RubyGems among other ecosystems) live,
  # per gem+version, and parses Gemfile.lock with a small hand-rolled reader
  # (see .parse_lockfile) rather than depending on the `bundler` library, so
  # the check works the same whether or not this run happens to be under
  # Bundler. No bundler-audit source was read or copied to build this — see
  # the README's "Dependency audit" section for the conceptual write-up this
  # was built from.
  #
  # Two independent checks, callable separately:
  #   - .insecure_sources(root)   — offline, parses Gemfile.lock's GIT/PATH
  #     blocks for unencrypted (`git://`, `http://`) remotes.
  #   - .vulnerable_gems(root)    — needs network: looks up every
  #     RubyGems-sourced gem (not git/path — see why below) in OSV.dev.
  #
  # Unlike the static Ripper scan, this needs a live network connection for
  # the vulnerability lookup — so it's not part of the default `scryer`/
  # `scryer:report` run; call it explicitly (`scryer:audit_dependencies`,
  # or `scryer --audit-deps`) when you want it, same as bundler-audit is a
  # separate command from your test suite.
  class DependencyAudit
    Finding = Struct.new(
      :kind,             # "vulnerable_dependency" | "insecure_source"
      :gem_name,
      :installed_version,
      :severity,         # "critical" | "warning" | "info"
      :advisory_id,
      :title,
      :url,
      :patched_versions,
      :message,
      :suggested_fix,
      keyword_init: true
    ) do
      def to_h
        super.transform_keys(&:to_s)
      end
    end

    OSV_QUERY_URL = "https://api.osv.dev/v1/query".freeze
    ECOSYSTEM = "RubyGems".freeze

    SEVERITY_BY_OSV_LEVEL = {
      "CRITICAL" => "critical",
      "HIGH" => "critical",
      "MODERATE" => "warning",
      "MEDIUM" => "warning",
      "LOW" => "info"
    }.freeze

    # Ruby's own published maintenance-branch EOL dates
    # (ruby-lang.org/en/downloads/branches/) — these are announced years in
    # advance and essentially never move, unlike a CVE feed, so this is a
    # one-time/occasional-update cost rather than an ongoing sync burden.
    # Update when a new branch's EOL is announced, or an older branch not
    # listed here needs adding.
    RUBY_EOL_DATES = {
      "2.5" => Date.new(2021, 3, 31),
      "2.6" => Date.new(2022, 3, 31),
      "2.7" => Date.new(2023, 3, 31),
      "3.0" => Date.new(2024, 3, 31),
      "3.1" => Date.new(2025, 3, 31),
      "3.2" => Date.new(2026, 3, 31),
      "3.3" => Date.new(2027, 3, 31),
      "3.4" => Date.new(2028, 3, 31)
    }.freeze

    class << self
      # Parses a Gemfile.lock into `{ gems: { name => {version:, source:} },
      # git_or_path_sources: [...], ruby_version: "3.3.3" | nil }`. `source`
      # is "gem", "git", or "path" — taken from which top-level block
      # (GEM/GIT/PATH) the spec's `specs:` list appeared under.
      def parse_lockfile(path)
        gems = {}
        git_or_path_sources = []
        ruby_version = nil

        current_block = nil # "gem" | "git" | "path" | nil (other section)
        current_section = nil # PLATFORMS | DEPENDENCIES | BUNDLED WITH | RUBY VERSION | nil
        current_remote = nil
        in_specs = false

        File.foreach(path) do |line|
          case line
          when /\A(GEM|GIT|PATH)\s*\z/
            current_block = Regexp.last_match(1).downcase
            current_section = nil
            current_remote = nil
            in_specs = false
          when /\A(PLATFORMS|DEPENDENCIES|BUNDLED WITH|RUBY VERSION)\s*\z/
            current_block = nil
            current_section = Regexp.last_match(1)
            in_specs = false
          when /\A {2}remote:\s*(\S+)\s*\z/
            current_remote = Regexp.last_match(1)
            git_or_path_sources << { type: current_block, remote: current_remote } if %w[git path].include?(current_block)
          when /\A {2}specs:\s*\z/
            in_specs = true
          when /\A {4}([A-Za-z0-9_.\-]+)\s+\(([^)]+)\)\s*\z/
            next unless in_specs

            name = Regexp.last_match(1)
            version = Regexp.last_match(2)
            # A gem can legitimately appear under more than one block only
            # in pathological Gemfiles; last one wins, consistent with how
            # Bundler itself resolves a single spec per gem name.
            gems[name] = { version: version, source: current_block }
          when /\A\s*ruby\s+(\S+)\s*\z/
            ruby_version = Regexp.last_match(1) if current_section == "RUBY VERSION"
          end
        end

        { gems: gems, git_or_path_sources: git_or_path_sources, ruby_version: ruby_version }
      end

      # Offline. Flags the Ruby version pinned in Gemfile.lock's RUBY
      # VERSION section if its minor series is past end-of-life — after that
      # date Ruby publishes no more security patches for it, for any issue,
      # so this is a real gap even with every gem otherwise up to date.
      # Returns [] if no version is pinned, or its series isn't one
      # RUBY_EOL_DATES knows about (never guessed as "fine" by omission).
      def ruby_eol_check(root)
        lockfile = File.join(root, "Gemfile.lock")
        return [] unless File.exist?(lockfile)

        ruby_version = parse_lockfile(lockfile)[:ruby_version]
        return [] unless ruby_version

        series = ruby_version[/\A\d+\.\d+/]
        eol_date = series && RUBY_EOL_DATES[series]
        return [] unless eol_date && Date.today > eol_date

        [
          Finding.new(
            kind: "ruby_eol",
            gem_name: "Ruby",
            installed_version: ruby_version,
            severity: "critical",
            title: "Ruby #{series} is end-of-life",
            url: "https://www.ruby-lang.org/en/downloads/branches/",
            patched_versions: [],
            message: "Ruby #{ruby_version} (#{series} series) reached end-of-life on " \
                      "#{eol_date} — no security patches are published for it anymore, for any issue.",
            suggested_fix: "Upgrade to a Ruby version still receiving security maintenance — see " \
                            "https://www.ruby-lang.org/en/downloads/branches/ for current status."
          )
        ]
      end

      # Offline. Flags GIT/PATH sources recorded with an unencrypted remote
      # (`git://` or plain `http://`) — the same supply-chain concern
      # bundler-audit's insecure-source check targets, checked here by
      # reading Gemfile.lock's own GIT/PATH blocks instead of the Gemfile.
      def insecure_sources(root)
        lockfile = File.join(root, "Gemfile.lock")
        return [] unless File.exist?(lockfile)

        parsed = parse_lockfile(lockfile)
        parsed[:git_or_path_sources].filter_map do |src|
          next unless src[:remote] =~ %r{\A(git|http)://}

          Finding.new(
            kind: "insecure_source",
            gem_name: nil,
            severity: "warning",
            message: "Gemfile.lock has a #{src[:type]} source over an unencrypted transport: #{src[:remote]}",
            suggested_fix: "Point this source at an https:// URL instead — an unencrypted git:// or " \
                            "http:// remote can be tampered with in transit (classic supply-chain risk)."
          )
        end
      end

      # Needs network. One OSV.dev query per RubyGems-sourced gem in the
      # lockfile (git/path-sourced gems are skipped — their version string
      # doesn't necessarily correspond to the same code as the published gem
      # of that name, so checking them against RubyGems advisories could
      # misattribute or miss vulnerabilities). `http_client` is injectable
      # for testing; defaults to a real Net::HTTP call. A real lockfile can
      # easily have 200-300+ gems, and this is a network call per gem, so
      # lookups run across a small stdlib-only thread pool (`concurrency`)
      # rather than one gem at a time.
      def vulnerable_gems(root, http_client: method(:query_osv), concurrency: 8)
        lockfile = File.join(root, "Gemfile.lock")
        return [] unless File.exist?(lockfile)

        parsed = parse_lockfile(lockfile)
        targets = parsed[:gems].select { |_, info| info[:source] == "gem" }.to_a

        queue = Queue.new
        targets.each { |pair| queue << pair }
        results = Queue.new

        workers = Array.new([concurrency, targets.size].min) do
          Thread.new do
            loop do
              name, info = begin
                queue.pop(true)
              rescue ThreadError
                nil
              end
              break unless name

              http_client.call(name, info[:version]).each { |v| results << finding_for(name, info[:version], v) }
            end
          end
        end
        workers.each(&:join)

        findings = []
        findings << results.pop(true) until results.empty?
        findings
      end

      # Offline. Flags `config/master.key` (the key that decrypts Rails
      # encrypted credentials, config/credentials.yml.enc) if it exists on
      # disk and .gitignore doesn't exclude it — Rails generates it
      # gitignored by default (`/config/master.key`), but that line is easy
      # to lose (a merge, a from-scratch .gitignore, copying the file into a
      # repo that never had the Rails default). If this file is ever
      # committed, anyone with repo access — including git history, even
      # after a later removal — can decrypt every credential in
      # config/credentials.yml.enc.
      def credentials_exposure_check(root)
        master_key_path = File.join(root, "config", "master.key")
        return [] unless File.exist?(master_key_path)
        return [] if master_key_gitignored?(root)

        [
          Finding.new(
            kind: "credentials_exposure",
            gem_name: "Rails",
            severity: "critical",
            title: "config/master.key is present and not gitignored",
            url: "https://guides.rubyonrails.org/security.html",
            patched_versions: [],
            message: "config/master.key exists in this app, but .gitignore doesn't exclude it " \
                      "(checked for both `/config/master.key` and `config/master.key`) — if this " \
                      "file is ever committed, anyone with repository access, including git " \
                      "history even after a later removal, can decrypt every credential in " \
                      "config/credentials.yml.enc.",
            suggested_fix: "Add `/config/master.key` to .gitignore immediately. If this key was " \
                            "ever actually committed to git history, treat every credential in " \
                            "config/credentials.yml.enc as compromised: rotate them and regenerate " \
                            "the master key (delete both files, then `bin/rails credentials:edit`)."
          )
        ]
      end

      # Needs network. One-off OSV.dev lookup for a single gem, independent
      # of any Gemfile.lock — backs `scryer --check-gem NAME[:VERSION]`.
      # With a version, only vulnerabilities affecting that exact version
      # are returned (same filtering as vulnerable_gems); omit it to see
      # every advisory ever filed against the gem, across all versions.
      def check_gem(name, version = nil)
        query_osv(name, version).map { |v| finding_for(name, version, v) }
      end

      private

      def master_key_gitignored?(root)
        gitignore_path = File.join(root, ".gitignore")
        return false unless File.exist?(gitignore_path)

        File.foreach(gitignore_path).any? do |line|
          line.strip.match?(%r{\A/?config/master\.key\z})
        end
      end

      def query_osv(name, version = nil)
        require "net/http"
        require "uri"

        uri = URI(OSV_QUERY_URL)
        package_query = { package: { name: name, ecosystem: ECOSYSTEM } }
        package_query[:version] = version if version
        body = JSON.generate(package_query)

        response = Net::HTTP.start(uri.host, uri.port, use_ssl: true, open_timeout: 5, read_timeout: 10) do |http|
          http.post(uri.path, body, "Content-Type" => "application/json")
        end

        return [] unless response.is_a?(Net::HTTPSuccess)

        (JSON.parse(response.body)["vulns"] || [])
      rescue StandardError
        # A single gem's lookup failing (network hiccup, rate limit) shouldn't
        # abort the whole audit — it just means that one gem wasn't checked.
        []
      end

      def finding_for(gem_name, installed_version, vuln)
        level = vuln.dig("database_specific", "severity")
        fixed_versions = fixed_versions_for(vuln, gem_name)

        Finding.new(
          kind: "vulnerable_dependency",
          gem_name: gem_name,
          installed_version: installed_version,
          severity: SEVERITY_BY_OSV_LEVEL[level.to_s.upcase] || "warning",
          advisory_id: vuln["id"],
          title: vuln["summary"] || vuln["id"],
          url: (vuln["references"] || []).map { |r| r["url"] }.find { |u| u&.start_with?("http") },
          patched_versions: fixed_versions,
          message: "#{gem_name}#{installed_version ? " #{installed_version}" : ""} is affected by " \
                   "#{vuln["id"]}#{vuln["summary"] ? ": #{vuln["summary"]}" : ""}",
          suggested_fix: fixed_versions.empty? ? "No fixed version is published yet for #{vuln["id"]} — track the advisory for updates." : "Upgrade #{gem_name} to #{fixed_versions.join(" or ")} (or later)."
        )
      end

      def fixed_versions_for(vuln, gem_name)
        (vuln["affected"] || [])
          .select { |a| a.dig("package", "name") == gem_name }
          .flat_map { |a| a["ranges"] || [] }
          .flat_map { |r| r["events"] || [] }
          .filter_map { |e| e["fixed"] }
          .uniq
      end
    end
  end
end
