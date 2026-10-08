if ENV.delete('COVERAGE')
  require 'simplecov'

  SimpleCov.start do
    coverage :line
    coverage :branch
    cover "lib/**/*.rb"
    group('Missing'){|src| src.covered_percent < 100}
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
    SimpleLdapAuthenticator.single_threaded = false
  end

  after do
    sc = SimpleLdapAuthenticator.singleton_class
    if sc.method_defined?(:orig_new_connection)
      sc.send(:remove_method, :new_connection)
      sc.send(:alias_method, :new_connection, :orig_new_connection)
      sc.send(:remove_method, :orig_new_connection)
    end
  end

  [false, true].each do |single_threaded|
    [nil, 'ldap'].each do |use_ldap|
      [true, false].each do |use_logger|
        it ".valid? should return whether the login/password is valid with #{use_ldap ? "ldap" : "net/ldap"} with#{'out' unless use_logger} a logger#{' in single threaded mode' if single_threaded}" do
          SimpleLdapAuthenticator.single_threaded = single_threaded
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
            SimpleLdapAuthenticator.singleton_class.send(:alias_method, :orig_new_connection, :new_connection)
            def SimpleLdapAuthenticator.new_connection(server)
              conn = orig_new_connection(server)
              def conn.bind(login, password)
                raise LDAP::ResultError, 'Invalid credentials' unless password == 'password'
              end
              def conn.unbind
              end
              def conn.bound?
                true
              end
              conn
            end
          end
          SimpleLdapAuthenticator.valid?('user', 'password').must_equal true
          SimpleLdapAuthenticator.valid?('user', 'password2').must_equal false
          if use_logger && !use_ldap
            logger.last.must_equal [:info, "Error attempting to authenticate user by 127.0.0.1: 49 Invalid Credentials Make my day"]
          end
        end
      end
    end
  end

  it ".valid? should use a separate connection per call by default" do
    SimpleLdapAuthenticator.valid?('user', 'password').must_equal true
    SimpleLdapAuthenticator.instance_variable_get(:@connection).must_be_nil
  end

  it ".valid? should reuse the same connection in single threaded mode" do
    SimpleLdapAuthenticator.single_threaded = true
    SimpleLdapAuthenticator.valid?('user', 'password').must_equal true
    conn = SimpleLdapAuthenticator.connection
    conn.must_be_kind_of Net::LDAP
    SimpleLdapAuthenticator.valid?('user', 'password').must_equal true
    SimpleLdapAuthenticator.connection.must_be_same_as conn
  end

  it ".valid? should be thread-safe by default" do
    SimpleLdapAuthenticator.logger = nil
    false_true = 0
    5.times do
      q = Queue.new
      bad = Array.new(10){Thread.new{q.pop; SimpleLdapAuthenticator.valid?('user', 'password2')}}
      good = Array.new(10){Thread.new{q.pop; SimpleLdapAuthenticator.valid?('user', 'password')}}
      20.times{q << true}
      false_true += bad.count{|t| t.value}
      good.map(&:value).must_equal([true]*10)
    end
    false_true.must_equal 0
  end

  it ".switch_server should only switch servers if the given server is still the current server" do
    s1, s2 = SimpleLdapAuthenticator.servers
    SimpleLdapAuthenticator.switch_server(s1)
    SimpleLdapAuthenticator.server.must_be_same_as s2
    SimpleLdapAuthenticator.switch_server(s1)
    SimpleLdapAuthenticator.server.must_be_same_as s2
    SimpleLdapAuthenticator.switch_server
    SimpleLdapAuthenticator.server.must_be_same_as s1
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
