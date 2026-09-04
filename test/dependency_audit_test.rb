require_relative "test_helper"
require "tmpdir"

# Scryer::DependencyAudit.parse_lockfile — no network involved here (that's
# vulnerable_gems/query_osv's job); this is purely about correctly reading
# gem name/version pairs out of a Gemfile.lock's GEM/specs: block.
class DependencyAuditTest < Minitest::Test
  def write_lockfile(contents)
    dir = Dir.mktmpdir("scryer_dependency_audit_test")
    path = File.join(dir, "Gemfile.lock")
    File.write(path, contents)
    path
  end

  # Regression test: a platform-specific gem's lockfile spec line looks like
  # "nokogiri (1.19.4-x86_64-linux-musl)" — Bundler appends the platform as
  # a hyphen-separated suffix on the version itself. Left unstripped, this
  # got sent straight to OSV.dev's version filter in vulnerable_gems, which
  # parses the "-x86_64-linux-musl" suffix as a semver prerelease marker —
  # sorting the version as *older* than the plain release and matching every
  # advisory fixed at-or-before it as if it were still open. Confirmed
  # directly against OSV.dev: querying nokogiri "1.19.4-x86_64-linux-musl"
  # returned 8 vulns; querying the real version, "1.19.4", returned 0.
  def test_strips_platform_suffix_from_gem_version
    lockfile = write_lockfile(<<~LOCK)
      GEM
        remote: https://rubygems.org/
        specs:
          nokogiri (1.19.4-x86_64-linux-musl)
            racc (~> 1.4)
          racc (1.8.1)

      PLATFORMS
        x86_64-linux-musl

      DEPENDENCIES
        nokogiri
    LOCK

    parsed = Scryer::DependencyAudit.parse_lockfile(lockfile)

    assert_equal "1.19.4", parsed[:gems]["nokogiri"][:version]
    assert_equal "1.8.1", parsed[:gems]["racc"][:version]
  end

  def test_leaves_ordinary_version_untouched
    lockfile = write_lockfile(<<~LOCK)
      GEM
        remote: https://rubygems.org/
        specs:
          rack (3.2.7)

      PLATFORMS
        ruby

      DEPENDENCIES
        rack
    LOCK

    parsed = Scryer::DependencyAudit.parse_lockfile(lockfile)

    assert_equal "3.2.7", parsed[:gems]["rack"][:version]
  end
end
