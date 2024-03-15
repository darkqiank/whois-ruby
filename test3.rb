require 'whois'
require 'whois-parser'

ad = Whois::Server.guess("darkqiank.work")
puts ad.host
parser = ad.lookup("darkqiank.work").parser
puts parser.status
puts parser.registrar
