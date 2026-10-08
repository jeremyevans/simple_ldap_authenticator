# Minimal LDAPS server used for testing TLS certificate verification.
# Only supports simple binds, which succeed for any user if the password
# is "password".
#
# Usage: ruby test/ldapsserver.rb cert.pem key.pem port

require 'socket'
require 'openssl'
require 'net/ldap'

cert_file, key_file, port = ARGV
ctx = OpenSSL::SSL::SSLContext.new
ctx.cert = OpenSSL::X509::Certificate.new(File.read(cert_file))
ctx.key = OpenSSL::PKey::RSA.new(File.read(key_file))
server = OpenSSL::SSL::SSLServer.new(TCPServer.new('127.0.0.1', port.to_i), ctx)
# Do the TLS handshake in the connection thread, so a client that does
# not complete the handshake does not block other connections.
server.start_immediately = false

loop do
  socket = server.accept

  Thread.new(socket) do |s|
    begin
      s.accept
      while (pdu = s.read_ber(Net::LDAP::AsnSyntax))
        # Only handle bind requests
        break unless pdu[1].ber_identifier == 0x60
        code = pdu[1][2] == 'password' ? 0 : 49
        s.write([pdu[0].to_ber, [code.to_ber_enumerated, "".to_ber, "".to_ber].to_ber_appsequence(1)].to_ber_sequence)
      end
    rescue StandardError
      nil
    ensure
      s.close rescue nil
    end
  end
end
