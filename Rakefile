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

desc "Generate rdoc"
task :rdoc do
  rdoc_dir = "rdoc"
  rdoc_opts = ["--line-numbers", "--inline-source", '--title', 'simple_ldap_authenticator: Easy authentication to an LDAP server(s)']

  begin
    gem 'hanna'
    rdoc_opts.concat(['-f', 'hanna'])
  rescue Gem::LoadError
  end

  rdoc_opts.concat(['--main', 'README', "-o", rdoc_dir] +
    %w"README CHANGELOG LICENSE lib/simple_ldap_authenticator.rb"
  )

  FileUtils.rm_rf(rdoc_dir)

  require "rdoc"
  RDoc::RDoc.new.document(rdoc_opts)
end
