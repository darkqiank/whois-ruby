require 'whois'

client = Whois::Client.new
response = client.lookup("baidu.com")

puts response

