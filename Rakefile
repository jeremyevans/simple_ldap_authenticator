require 'rake'
require 'rake/clean'
require 'rake/rdoctask'

Rake::RDocTask.new do |rdoc|
  rdoc.rdoc_dir = "rdoc"
  rdoc.options += ["--quiet", "--line-numbers", "--inline-source"]
  rdoc.main = "README"
  rdoc.title = "simple_ldap_authenticator: Easy authentication to an LDAP server(s)"
  rdoc.rdoc_files.add ["README", "LICENSE", "lib/simple_ldap_authenticator.rb"]
end

desc "Package simple_ldap_authenticator"
task :package do
  sh %{gem build simple_ldap_authenticator.gemspec}
end
