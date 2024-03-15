require 'whois-parser'

record = Whois.whois("catflix.cn")
# => #<Whois::Record>

parser = record.parser
# => #<Whois::Parser>

parser.available?
# => false
parser.registered?
# => true

puts parser.created_on
# => Fri Dec 10 00:00:00 +0100 1999

# tech = parser.technical_contacts.first
# => #<Whois::Record::Contact>
# puts tech.id
# => "TS7016-ITNIC"
# puts tech.name
# => "Technical Services"

# parser.nameservers.each do |nameserver|
#  puts nameserver
#end
