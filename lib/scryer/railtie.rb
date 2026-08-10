module Scryer
  # This gem runs on-demand via a rake task, not as request-cycle
  # instrumentation — so the Railtie doesn't need to hook into the
  # middleware stack or boot process at all. Its only job is to make sure
  # requiring this gem inside a Rails app never raises, and to load the
  # rake tasks into the host app's Rails console/`rake -T` listing.
  class Railtie < Rails::Railtie
    rake_tasks do
      load File.expand_path("../tasks/scryer.rake", __dir__)
    end
  end
end
