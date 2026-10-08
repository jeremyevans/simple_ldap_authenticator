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
require 'openssl'
require 'tmpdir'
require 'fileutils'
require 'stringio'

tls_dir = Dir.mktmpdir

# Make libldap trust the system certificate by default.  This needs to be
# set before libldap is initialized.
ENV['LDAPTLS_CACERT'] = File.join(tls_dir, "system.crt")

require 'net/ldap'
require 'ldap'

ruby = ENV['RUBY'] || 'ruby'
port = (ENV['PORT'] || 43890).to_i
logger = []
def logger.method_missing(*a)
  self << a
end

# Only run SSL specs on supported Ruby versions (anyone running unsupported
# versions likely doesn't care about security anyway)
ssl_specs = RUBY_VERSION >= '3.3'

tls_cert_files = {}
pids = [Process.spawn(ruby, 'test/ldapserver.rb')]

# Create self-signed certificates for the LDAPS servers, one valid for
# localhost/127.0.0.1, one valid for a different hostname, and one valid for
# 127.0.0.1 that libldap trusts by default (see LDAPTLS_CACERT above).
if ssl_specs
  [['good', 'DNS:localhost,IP:127.0.0.1', port+1], ['bad', 'DNS:wrong.example', port+2], ['system', 'IP:127.0.0.1', port+3]].each do |name, san, tls_port|
    key = OpenSSL::PKey::RSA.new(2048)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = cert.issuer = OpenSSL::X509::Name.parse("/CN=#{name}")
    cert.public_key = key.public_key
    cert.not_before = Time.now - 3600
    cert.not_after = Time.now + 3600
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = ef.issuer_certificate = cert
    cert.add_extension(ef.create_extension("basicConstraints", "CA:TRUE", true))
    cert.add_extension(ef.create_extension("subjectAltName", san))
    cert.sign(key, OpenSSL::Digest.new("SHA256"))
    cert_file = tls_cert_files[name] = File.join(tls_dir, "#{name}.crt")
    key_file = File.join(tls_dir, "#{name}.key")
    File.write(cert_file, cert.to_pem)
    File.write(key_file, key.to_pem)
    pids << Process.spawn(ruby, 'test/ldapsserver.rb', cert_file, key_file, tls_port.to_s)
  end
end
sleep 1
servers = [String.new('127.0.0.1'), String.new('127.0.0.1')]

Minitest.after_run do
  pids.each do |pid|
    Process.kill('TERM', pid)
    Process.waitpid(pid)
  end
  FileUtils.rm_rf(tls_dir)
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

  if ssl_specs
    ['net/ldap', 'ldap'].each do |lib|
      describe "with use_ssl using #{lib}" do
        before do
          SimpleLdapAuthenticator.ldap_library = lib
          SimpleLdapAuthenticator.port = port+1
          # For net/ldap, use a hostname instead of an IP address, as net-ldap
          # uses the host for SNI, and LibreSSL does not allow IP addresses
          # for SNI.  For ldap, use an IP address, as libldap replaces
          # localhost with the system's hostname when verifying the
          # certificate.
          host = lib == 'net/ldap' ? 'localhost' : '127.0.0.1'
          SimpleLdapAuthenticator.servers = [String.new(host), String.new(host)]
        end

        # Suppress net/ldap warning when not verifying certificates
        def no_warnings
          stderr = $stderr
          $stderr = StringIO.new
          yield
        ensure
          $stderr = stderr
        end

        it ".valid? should not accept an untrusted server certificate if verifying" do
          SimpleLdapAuthenticator.use_ssl = {:verify_mode=>OpenSSL::SSL::VERIFY_PEER}
          SimpleLdapAuthenticator.valid?('user', 'password').must_equal false
        end

        it ".valid? should accept a server certificate signed by a trusted CA" do
          SimpleLdapAuthenticator.use_ssl = {:ca_file=>tls_cert_files['good']}
          SimpleLdapAuthenticator.valid?('user', 'password').must_equal true
          SimpleLdapAuthenticator.valid?('user', 'password2').must_equal false
        end

        it ".valid? should accept a server certificate signed by a trusted CA in single threaded mode" do
          SimpleLdapAuthenticator.single_threaded = true
          SimpleLdapAuthenticator.use_ssl = {:ca_file=>tls_cert_files['good']}
          SimpleLdapAuthenticator.valid?('user', 'password').must_equal true
          SimpleLdapAuthenticator.valid?('user', 'password').must_equal true
        end

        it ".valid? should accept a server certificate in a trusted CA directory" do
          Dir.mktmpdir do |dir|
            cert = OpenSSL::X509::Certificate.new(File.read(tls_cert_files['good']))
            File.write(File.join(dir, "%08x.0" % cert.subject.hash), cert.to_pem)
            SimpleLdapAuthenticator.use_ssl = {:ca_path=>dir}
            SimpleLdapAuthenticator.valid?('user', 'password').must_equal true
          end
        end

        it ".valid? should not accept a trusted server certificate for a different hostname" do
          SimpleLdapAuthenticator.port = port+2
          SimpleLdapAuthenticator.use_ssl = {:ca_file=>tls_cert_files['bad']}
          SimpleLdapAuthenticator.valid?('user', 'password').must_equal false
        end

        it ".valid? should accept any server certificate if not verifying" do
          SimpleLdapAuthenticator.port = port+2
          SimpleLdapAuthenticator.use_ssl = {:verify_mode=>OpenSSL::SSL::VERIFY_NONE}
          no_warnings{SimpleLdapAuthenticator.valid?('user', 'password')}.must_equal true
        end

        if lib == 'ldap'
          it ".valid? should raise for unsupported TLS options" do
            SimpleLdapAuthenticator.use_ssl = {:bad=>true}
            proc{SimpleLdapAuthenticator.valid?('user', 'password')}.must_raise ArgumentError
          end
        else
          it ".valid? should support any SSLContext#set_params option" do
            store = OpenSSL::X509::Store.new
            store.add_file(tls_cert_files['good'])
            SimpleLdapAuthenticator.use_ssl = {:cert_store=>store}
            SimpleLdapAuthenticator.valid?('user', 'password').must_equal true
          end

          # For ldap, this depends on TLS_REQCERT not being set to allow/never
          # in the system's ldap.conf, and we cannot ensure that.
          it ".valid? should not accept an untrusted server certificate by default" do
            SimpleLdapAuthenticator.use_ssl = true
            SimpleLdapAuthenticator.valid?('user', 'password').must_equal false
          end
        end
      end
    end
  end

  [[true, port+3, true], [{}, port+3, true], [{:ca_file=>tls_cert_files['good']}, port+1, false]].each do |use_ssl, ssl_port, reuse|
    it ".valid? should #{'not ' unless reuse}reuse the connection in single threaded mode with ldap and use_ssl = #{use_ssl.inspect}" do
      SimpleLdapAuthenticator.single_threaded = true
      SimpleLdapAuthenticator.ldap_library = 'ldap'
      SimpleLdapAuthenticator.use_ssl = use_ssl
      SimpleLdapAuthenticator.port = ssl_port
      SimpleLdapAuthenticator.valid?('user', 'password').must_equal true
      conn = SimpleLdapAuthenticator.instance_variable_get(:@connection)
      SimpleLdapAuthenticator.valid?('user', 'password').must_equal true
      if reuse
        conn.must_be_kind_of LDAP::SSLConn
        SimpleLdapAuthenticator.instance_variable_get(:@connection).must_be_same_as conn
      else
        conn.must_be_nil
        SimpleLdapAuthenticator.instance_variable_get(:@connection).must_be_nil
      end
    end
  end if ssl_specs

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
