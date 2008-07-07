spec = Gem::Specification.new do |s| 
  s.name = "simple_ldap_authenticator"
  s.version = "1.0.0"
  s.author = "Jeremy Evans"
  s.email = "code@jeremyevans.net"
  s.platform = Gem::Platform::RUBY
  s.summary = "Easy authentication to an LDAP server(s)"
  s.files = ["README", "LICENSE", "lib/simple_ldap_authenticator.rb"]
  s.extra_rdoc_files = ["LICENSE"]
  s.require_paths = ["lib"]
  s.has_rdoc = true
  s.rdoc_options = %w'--inline-source --line-numbers README lib'
end
