# Minimal LDAP server used for testing.  Only supports simple binds, which
# succeed for the "user" user if the password is "password".
#
# Usage: ruby test/ldapserver.rb
#
# Uses the PORT environment variable for the port (default: 43890).

require 'socket'
require 'net/ldap'

def send_bind_response(socket, message_id, code, dn, text)
  socket.write([message_id.to_ber, [code.to_ber_enumerated, dn.to_ber, text.to_ber].to_ber_appsequence(1)].to_ber_sequence)
end

def handle_bind_request(socket, message_id, request)
  version, dn, auth = request
  # Accept LDAPv2 binds, as Ruby/LDAP uses LDAPv2 by default for non-SSL
  # connections, and simple binds are the same for LDAPv2 and LDAPv3.
  if !(version == 2 || version == 3) || dn == "bad_version"
    send_bind_response(socket, message_id, 2, "", "We only support versions 2 and 3")
  elsif dn != "user"
    send_bind_response(socket, message_id, 48, "", "Who are you?")
  elsif auth.ber_identifier != 0x80
    send_bind_response(socket, message_id, 7, "", "Keep it simple, man")
  elsif auth != "password"
    send_bind_response(socket, message_id, 49, "", "Make my day")
  else
    send_bind_response(socket, message_id, 0, dn, "I'll take it")
  end
end

server = TCPServer.new('127.0.0.1', (ENV['PORT'] || 43890).to_i)

loop do
  Thread.new(server.accept) do |socket|
    begin
      while (pdu = socket.read_ber(Net::LDAP::AsnSyntax))
        # Only handle bind requests, close connection on any other request
        # (including unbind requests).
        break unless pdu[1].ber_identifier == 0x60
        handle_bind_request(socket, pdu[0], pdu[1])
      end
    rescue StandardError
      nil
    ensure
      socket.close rescue nil
    end
  end
end
