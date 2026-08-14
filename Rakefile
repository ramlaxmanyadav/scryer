require "rake/testtask"

Rake::TestTask.new(:test) do |t|
  t.libs << "test" << "lib"
  t.test_files = FileList["test/**/*_test.rb"]
  t.verbose = true
end

desc "Run the accuracy benchmark (benchmark/run.rb) — precision/recall/F1 per rule against the " \
     "hand-labeled corpus in benchmark/corpus.rb. See benchmark/README.md for methodology."
task :benchmark do
  ruby "benchmark/run.rb"
end

task default: :test
