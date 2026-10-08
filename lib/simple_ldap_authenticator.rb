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
# * use_ssl = true # for logging in via LDAPS
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
        Net::LDAP.new(:host=>server, :port=>(port), :encryption=>(:simple_tls if use_ssl))
      else
        (use_ssl ? LDAP::SSLConn : LDAP::Conn).new(server, port)
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
      connection = single_threaded ? self.connection : new_connection(server)
      if ldap_library == 'net/ldap'
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
        connection.unbind if connection.bound?
        begin
          connection.bind(login_format % login, password)
          connection.unbind
          logger.info("Authenticated #{login} by #{server}") if logger
          true
        rescue LDAP::ResultError => error
          connection.unbind if connection.bound?
          logger.info("Error attempting to authenticate #{login} by #{server}: #{error.message}") if logger
          switch_server(server) unless error.message == 'Invalid credentials'
          false
        end
      end
    end
  end
end
