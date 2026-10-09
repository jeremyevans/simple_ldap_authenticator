# SimpleLdapAuthenticator
#
# This plugin supports both Ruby/LDAP and Net::LDAP, defaulting to Ruby/LDAP
# if it is available.  If both are installed and you want to force the use of 
# Net::LDAP, set SimpleLdapAuthenticator.ldap_library = 'net/ldap'.

# Allows for easily authenticating users via LDAP (or LDAPS).  If authenticating
# via LDAP to a server running on localhost, you should only have to configure
# the login_format.
#
# Can be configured using the following accessors (with examples):
# * login_format = '%s@domain.com' # Active Directory, OR
# * login_format = 'cn=%s,cn=users,o=organization,c=us' # Other LDAP servers
# * servers = ['dc1.domain.com', 'dc2.domain.com'] # names/addresses of LDAP servers to use
# * use_ssl = true # for logging in via LDAPS, verifying the server certificate
# * use_ssl = {ca_file: '/path/to/ca.pem'} # for logging in via LDAPS, with TLS options
# * port = 3289 # instead of 389 for LDAP or 636 for LDAPS
# * logger = Logger.new($stdout) # for logging authentication successes/failures
# * single_threaded = true # reuse a single connection, only safe if not using threads
#
# By default, a new connection object is created for each call to valid?,
# so that valid? is safe to call concurrently from multiple threads.  If
# you are only using SimpleLdapAuthenticator in a single thread, you can set
# single_threaded = true, which reuses a single connection object for all
# calls to valid?.  Do not set single_threaded = true if valid? may be
# called concurrently, as that can result in invalid passwords being
# considered valid.
#
# When use_ssl is true, the server's certificate and hostname are verified
# using the default trusted certificates.  use_ssl can also be set to a hash
# of TLS options, which are merged into the default TLS options.  The
# following TLS options are supported for both libraries:
#
# :ca_file :: File containing trusted CA certificates.
# :ca_path :: Directory containing trusted CA certificates.
# :verify_mode :: Whether to verify the server certificate, should be
#                 OpenSSL::SSL::VERIFY_PEER or OpenSSL::SSL::VERIFY_NONE
#                 if given.
#
# For net/ldap, any option supported by OpenSSL::SSL::SSLContext#set_params
# can be used. For ldap, only the three keys given above work.
#
# Before version 2, use_ssl = true did not verify the server certificate
# when using net/ldap.  To restore that behavior (not recommended, as it allows
# man-in-the-middle attacks), you can disable verification:
#
#  SimpleLdapAuthenticator.use_ssl = {verify_mode: OpenSSL::SSL::VERIFY_NONE}
#
# With ldap, whether to verify the certificate by default depends on the
# system's libldap configuration (TLS_REQCERT in ldap.conf). The above setting
# also disables verification when using ldap.
#
# The class is used as a singleton, you are not supposed to create an
# instance of it. For example:
#
#  require 'simple_ldap_authenticator'
#
#  SimpleLdapAuthenticator.servers = %w'dc1.domain.com dc2.domain.com'
#  SimpleLdapAuthenticator.use_ssl = true
#  SimpleLdapAuthenticator.login_format = '%s@domain.com'
#
#  SimpleLdapAuthenticator.valid?(username, password)
#  # => true or false (or raise if there is an issue connecting to the server)
class SimpleLdapAuthenticator
  @servers = ['127.0.0.1']
  @use_ssl = false
  @login_format = '%s'
  @single_threaded = false
  @switch_server_mutex = Mutex.new

  class << self
    attr_accessor :servers, :use_ssl, :login_format, :logger, :ldap_library, :single_threaded
    attr_writer :port, :connection
    
    # Load the required LDAP library, either 'ldap' or 'net/ldap'
    def load_ldap_library
      return if @ldap_library_loaded
      if @ldap_library
        if @ldap_library == 'net/ldap'
          require 'net/ldap'
        else
          require 'ldap'
          require 'ldap/control'
        end
      else
        begin
          require 'ldap'
          require 'ldap/control'
          @ldap_library = 'ldap'
        rescue LoadError
          require 'net/ldap'
          @ldap_library = 'net/ldap'
        end
      end
      @ldap_library_loaded = true
    end
    
    # The next LDAP server to which to connect
    def server
      servers[0]
    end
    
    # The shared connection to the LDAP server, only used in single threaded
    # mode.  A single connection is made and the connection is only changed if
    # a server returns an error other than invalid password.
    def connection
      @connection ||= new_connection(server)
    end

    # Create a new connection object for the given LDAP server.
    def new_connection(server)
      load_ldap_library
      if ldap_library == 'net/ldap'
        if use_ssl
          tls_opts = use_ssl.is_a?(Hash) ? use_ssl.dup : {}
          unless tls_opts[:verify_mode]
            require "openssl"
            tls_opts[:verify_mode] = OpenSSL::SSL::VERIFY_PEER
          end
          encryption_opts = {:method=>:simple_tls, :tls_options=>tls_opts}
        end
        Net::LDAP.new(:host=>server, :port=>port, :encryption=>encryption_opts)
      elsif use_ssl
        conn = LDAP::SSLConn.new(server, port)
        if use_ssl.is_a?(Hash) && !use_ssl.empty?
          use_ssl.each do |k, v|
            case k
            when :verify_mode
              conn.set_option(LDAP::LDAP_OPT_X_TLS_REQUIRE_CERT, v)
            when :ca_file
              conn.set_option(LDAP::LDAP_OPT_X_TLS_CACERTFILE, v)
            when :ca_path
              conn.set_option(LDAP::LDAP_OPT_X_TLS_CACERTDIR, v)
            else
              raise ArgumentError, "unsupported TLS option for ldap library: #{k.inspect}"
            end
          end
          conn.set_option(LDAP::LDAP_OPT_X_TLS_NEWCTX, 0)
        end
        conn
      else
        LDAP::Conn.new(server, port)
      end
    end
    
    # The port to use.  Defaults to 389 for LDAP and 636 for LDAPS.
    def port
      @port ||= use_ssl ? 636 : 389
    end
    
    # Disconnect from current LDAP server and use a different LDAP server on the
    # next authentication attempt.  If failed_server is given, only switch
    # servers if failed_server is still the current server, so that multiple
    # threads failing on the same server only switch servers once.
    def switch_server(failed_server = nil)
      @switch_server_mutex.synchronize do
        if failed_server.nil? || server.equal?(failed_server)
          self.connection = nil
          servers.rotate!
        end
      end
    end
    
    # Check the validity of a login/password combination
    def valid?(login, password)
      login = login.to_s
      password = password.to_s
      return false if password == '' || password.include?("\0") || login.include?("\0")

      server = self.server
      if ldap_library == 'net/ldap'
        connection = single_threaded ? self.connection : new_connection(server)
        auth = {:method=>:simple, :username=>login_format % login, :password=>password}
        begin
          if connection.bind(auth)
            logger.info("Authenticated #{login} by #{server}") if logger
            true
          else
            result = connection.get_operation_result
            if logger
              logger.info("Error attempting to authenticate #{login} by #{server}: #{result.code} #{result.message} #{result.error_message.to_s.strip}")
            end
            switch_server(server) unless result.code == 49
            false
          end
        rescue Net::LDAP::Error, SocketError, SystemCallError => error
          logger.info("Error attempting to authenticate #{login} by #{server}: #{error.message}") if logger
          switch_server(server)
          false
        end
      else
        connection = (single_threaded && !(use_ssl.is_a?(Hash) && !use_ssl.empty?)) ? self.connection : new_connection(server)
        connection.unbind if connection.bound?
        begin
          connection.bind(login_format % login, password)
          connection.unbind
          logger.info("Authenticated #{login} by #{server}") if logger
          true
        rescue LDAP::ResultError => error
          logger.info("Error attempting to authenticate #{login} by #{server}: #{error.message}") if logger
          switch_server(server) unless error.message == 'Invalid credentials'
          false
        end
      end
    end
  end
end
