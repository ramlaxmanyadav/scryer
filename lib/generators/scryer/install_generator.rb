require "rails/generators"

module Scryer
  module Generators
    # `rails generate scryer:install` — drops a commented initializer
    # into the host app. Doesn't touch anything else; the rake tasks are
    # already loaded automatically by the Railtie. See
    # lib/generators/scryer/USAGE for the detailed description shown by
    # `bin/rails generate scryer:install --help`.
    class InstallGenerator < Rails::Generators::Base
      source_root File.expand_path("templates", __dir__)

      desc "Creates a config/initializers/scryer.rb initializer for static code analysis (security, duplicate code, performance heuristics)."

      def create_initializer
        template "scryer_initializer.rb", "config/initializers/scryer.rb"
      end

      def show_readme
        say ""
        say "Scryer installed. Next steps:", :green
        say "  1. (Optional) Edit config/initializers/scryer.rb to set project_name, dirs, or branch."
        say "  2. Run `bin/rails scryer:report` to scan this app and write tmp/scryer_report.{json,html}."
        say "     Add a dependency audit or a custom path with task args, e.g. `bin/rails 'scryer:report[html,deps]'`."
        say "  3. Open tmp/scryer_report.html in a browser to review findings — see README.md for what each section means."
      end
    end
  end
end
