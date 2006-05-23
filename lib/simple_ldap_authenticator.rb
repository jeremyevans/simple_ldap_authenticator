# SimpleLdapAuthenticator
require 'ldap'
require 'ldap/control'

# Allows for easily authenticated users via LDAP (or LDAPS).  If authenticated
# via LDAP to a server running on localhost, you should only have to configure
# the login_format.
#
# Can be configured using the following accessors (with examples):
# * login_format = '%s@domain.com' # Active Directory, OR
# * login_format = 'cn=%s,cn=users,o=organization,c=us' # Other LDAP servers
# * servers = ['dc1.domain.com', 'dc2.domain.com'] # names/addresses of LDAP servers to use
# * use_ssl = true # for logging in via LDAPS
# * port = 3289 # instead of 389 for LDAP or 636 for LDAPS
# * logger = RAILS_DEFAULT_LOGGER # for logging authentication successes/failures
#
# The class is used as a global variable, you are not supposed to create an
# instance of it. For example:
#
#    require 'simple_ldap_authenticator'
#    SimpleLdapAuthenticator.servers = %w'dc1.domain.com dc2.domain.com'
#    SimpleLdapAuthenticator.use_ssl = true
#    SimpleLdapAuthenticator.login_format = '%s@domain.com'
#    SimpleLdapAuthenticator.logger = RAILS_DEFAULT_LOGGER
#    class LoginController < ApplicationController 
#      def login
#        return redirect_to(:action=>'try_again') unless SimpleLdapAuthenticator.valid?(params[:username], params[:password])
#        session[:username] = params[:username]
#      end
#    end
class SimpleLdapAuthenticator
  class << self
    @servers = ['127.0.0.1']
    @use_ssl = false
    @login_format = '%s'
    attr_accessor :servers, :use_ssl, :port, :login_format, :logger, :connection
    
    # The next LDAP server to which to connect
    def server
      servers[0]
    end
    
    # Disconnect from current LDAP server and use a different LDAP server on the
    # next authentication attempt
    def switch_server
      self.connection = nil
      servers << servers.shift
    end
    
    # Check the validity of a login/password combination
    def valid?(login, password)
      self.connection ||= use_ssl ? LDAP::SSLConn.new(server, port || 636) : LDAP::Conn.new(server, port || 389)
      connection.unbind if connection.bound?
      begin
        connection.bind(login_format % login.to_s, password.to_s)
        connection.unbind
        logger.info("Authenticated #{login.to_s} by #{server}") if logger
        true
      rescue LDAP::ResultError => error
        connection.unbind if connection.bound?
        logger.info("Error attempting to authenticate #{login.to_s} by #{server}: #{error.message}") if logger
        switch_server unless error.message == 'Invalid credentials'
        false
      end
    end
  end
end