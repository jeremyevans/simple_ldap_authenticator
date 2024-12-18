require 'rake/clean'

CLEAN.include %w'*.gem coverage rdoc'

desc "Package simple_ldap_authenticator"
task :package do
  sh %{gem build simple_ldap_authenticator.gemspec}
end

### Specs

desc "Run tests"
task :test do
  ruby = ENV['RUBY'] ||= FileUtils::RUBY 
  sh "#{ruby} #{"-w" if RUBY_VERSION >= '3'} #{'-W:strict_unused_block' if RUBY_VERSION >= '3.4'} test/simple_ldap_authenticator_test.rb"
end

task :default => :test

desc "Run tests with coverage"
task :test_cov do
  ruby = ENV['RUBY'] ||= FileUtils::RUBY 
  ENV['COVERAGE'] = '1'
  sh "#{ruby} test/simple_ldap_authenticator_test.rb"
end

### RDoc

require "rdoc/task"

RDoc::Task.new do |rdoc|
  rdoc.rdoc_dir = "rdoc"
  rdoc.options += ['--inline-source', '--line-numbers', '--title', 'simple_ldap_authenticator: Easy authentication to an LDAP server(s)', '--main', 'README', '-f', 'hanna']
  rdoc.rdoc_files.add %w"README LICENSE lib/simple_ldap_authenticator.rb"
end
