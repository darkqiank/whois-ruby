require 'whois'
require 'whois-parser'

# ad = Whois::Server.guess("darkqiank.work")
# puts ad.host
# parser = ad.lookup("darkqiank.work").parser
# puts parser.status
# puts parser.registrar

whois_client = Whois::Client.new
record = whois_client.lookup("darkqiank.work")
puts record.server.host