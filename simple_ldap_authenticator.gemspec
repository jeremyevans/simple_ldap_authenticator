Gem::Specification.new do |s| 
  s.name = "simple_ldap_authenticator"
  s.version = "1.1.0"
  s.author = "Jeremy Evans"
  s.email = "code@jeremyevans.net"
  s.platform = Gem::Platform::RUBY
  s.summary = "Easy authentication to an LDAP server(s)"
  s.files = ["README", "LICENSE", "lib/simple_ldap_authenticator.rb"]
  s.extra_rdoc_files = ["LICENSE"]
  s.require_paths = ["lib"]
  s.rdoc_options = %w'--inline-source --line-numbers README lib'

  s.metadata          = { 
    'bug_tracker_uri'   => 'https://github.com/jeremyevans/simple_ldap_authenticator/issues',
    'changelog_uri'     => 'https://github.com/jeremyevans/simple_ldap_authenticator/blob/master/CHANGELOG',
    'mailing_list_uri'  => 'https://github.com/jeremyevans/simple_ldap_authenticator/discussions',
    "source_code_uri"   => 'https://github.com/jeremyevans/simple_ldap_authenticator'
  }

  s.add_development_dependency "minitest-global_expectations"
  s.add_development_dependency "eventmachine"
  s.add_development_dependency "net-ldap"
  s.add_development_dependency "ruby-ldap"
end
