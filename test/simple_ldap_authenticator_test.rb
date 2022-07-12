if ENV.delete('COVERAGE')
  require 'simplecov'

  SimpleCov.start do
    enable_coverage :branch
    add_filter "/test/"
    add_group('Missing'){|src| src.covered_percent < 100}
    add_group('Covered'){|src| src.covered_percent == 100}
  end
end

gem 'minitest'
ENV['MT_NO_PLUGINS'] = '1' # Work around stupid autoloading of plugins
require 'minitest/global_expectations/autorun'
require_relative '../lib/simple_ldap_authenticator'
require 'net/ldap'
require 'ldap'

ruby = ENV['RUBY'] || 'ruby'
port = (ENV['PORT'] || 43890).to_i
logger = []
def logger.method_missing(*a)
  self << a
end

pid = Process.spawn(ruby, 'test/ldapserver.rb')
sleep 1
servers = [String.new('127.0.0.1'), String.new('127.0.0.1')]

Minitest.after_run do
  Process.kill('TERM', pid)
  Process.waitpid(pid)
end

describe SimpleLdapAuthenticator do
  before do
    SimpleLdapAuthenticator.servers = servers
    SimpleLdapAuthenticator.port = port
    SimpleLdapAuthenticator.use_ssl = false
    SimpleLdapAuthenticator.logger = logger
    SimpleLdapAuthenticator.ldap_library = 'net/ldap'
    SimpleLdapAuthenticator.load_ldap_library
    SimpleLdapAuthenticator.connection = nil
  end

  [nil, 'ldap'].each do |use_ldap|
    [true, false].each do |use_logger|
      it ".valid? should return whether the login/password is valid with#{'out' unless use_logger} a logger" do
        SimpleLdapAuthenticator.ldap_library = 'ldap' if use_ldap
        SimpleLdapAuthenticator.logger = nil unless use_logger

        SimpleLdapAuthenticator.valid?('user2', 'password').must_equal false
        SimpleLdapAuthenticator.valid?('user', '').must_equal false
        SimpleLdapAuthenticator.valid?('bad_version', 'password').must_equal false

        SimpleLdapAuthenticator.port = port-1
        s1, s2 = SimpleLdapAuthenticator.servers
        SimpleLdapAuthenticator.valid?('user', 'password').must_equal false
        SimpleLdapAuthenticator.servers[0].must_be_same_as s2
        SimpleLdapAuthenticator.servers[1].must_be_same_as s1

        SimpleLdapAuthenticator.port = port
        if use_ldap
          # Ruby/LDAP returns protocol error for the toy ldap server the tests use,
          # so override bind directly to return the expected result.
          def (SimpleLdapAuthenticator.connection).bind(login, password)
            raise LDAP::ResultError, 'Invalid credentials' unless password == 'password'
          end
          def (SimpleLdapAuthenticator.connection).unbind
          end
          def (SimpleLdapAuthenticator.connection).bound?
            true
          end
        end
        SimpleLdapAuthenticator.valid?('user', 'password').must_equal true
        SimpleLdapAuthenticator.valid?('user', 'password2').must_equal false
      end
    end
  end

  it ".port should be 389 or 636 by default" do
    SimpleLdapAuthenticator.port = nil
    SimpleLdapAuthenticator.port.must_equal 389
    SimpleLdapAuthenticator.port = nil
    SimpleLdapAuthenticator.use_ssl = true
    SimpleLdapAuthenticator.port.must_equal 636
  end

  it ".connection should return an appropriate connection object based on ldap_library and use_ssl setting" do
    SimpleLdapAuthenticator.connection = nil
    SimpleLdapAuthenticator.connection.must_be_kind_of Net::LDAP

    SimpleLdapAuthenticator.connection = nil
    SimpleLdapAuthenticator.ldap_library = 'ldap'
    SimpleLdapAuthenticator.connection.must_be_kind_of LDAP::Conn

    SimpleLdapAuthenticator.connection = nil
    SimpleLdapAuthenticator.use_ssl = true
    SimpleLdapAuthenticator.connection.must_be_kind_of LDAP::SSLConn

    SimpleLdapAuthenticator.connection = nil
    SimpleLdapAuthenticator.ldap_library = 'net/ldap'
    SimpleLdapAuthenticator.connection.must_be_kind_of Net::LDAP
  end

  it ".load_ldap_library should try ldap first, then net/ldap if not specified" do
    SimpleLdapAuthenticator.instance_variable_set(:@ldap_library_loaded, nil)
    SimpleLdapAuthenticator.ldap_library = nil
    SimpleLdapAuthenticator.load_ldap_library
    SimpleLdapAuthenticator.ldap_library.must_equal 'ldap'

    begin
      def SimpleLdapAuthenticator.require(lib)
        raise LoadError unless lib == 'net/ldap'
      end
      SimpleLdapAuthenticator.instance_variable_set(:@ldap_library_loaded, nil)
      SimpleLdapAuthenticator.ldap_library = nil
      SimpleLdapAuthenticator.load_ldap_library
      SimpleLdapAuthenticator.ldap_library.must_equal 'net/ldap'
    ensure
      SimpleLdapAuthenticator.singleton_class.send(:remove_method, :require)
    end
  end

  it ".load_ldap_library should load ldap if specified" do
    SimpleLdapAuthenticator.instance_variable_set(:@ldap_library_loaded, nil)
    SimpleLdapAuthenticator.ldap_library = 'ldap'
    SimpleLdapAuthenticator.load_ldap_library
    SimpleLdapAuthenticator.ldap_library.must_equal 'ldap'
  end
end
