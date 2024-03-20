require 'whois'
require 'whois-parser'

# Handler for processing WHOIS lookups
Handler = Proc.new do |request, response|
  # Hypothetical method to split the request path and extract the domain parameter
  # This is an example and may need to be adapted to your specific environment
  path_segments = request.path.split('/')
  # Assuming the domain is the second segment following the pattern /whois/:domain
  domain = path_segments[2]  # Adjust index based on your actual request path structure

  if domain.nil? || domain.empty?
    response.status = 400
    response['Content-Type'] = 'application/json'
    response.body = {code: 105, msg: "domain parameter is required"}.to_json
    return
  end

  whois_client = Whois::Client.new

  begin
    whois_response = whois_client.lookup(domain)
    whois_server_host = whois_response.server.host

    def clean_invalid_utf8(string)
      string.encode('UTF-8', 'binary', invalid: :replace, undef: :replace, replace: '')
    end

    def encode_value(value)
      case value
      when String
        clean_invalid_utf8(value.force_encoding("UTF-8"))
      when Array
        value.map { |element| encode_value(element) }
      when Hash
        value.transform_values { |v| encode_value(v) }
      else
        if value.respond_to?(:to_h)
          encode_value(value.to_h)
        else
          value
        end
      end
    end

    result = {
      domain: domain,
      whois_server_host: whois_server_host,
      raw_data: encode_value(whois_response.content)
    }

    begin
      parser = whois_response.parser
      status = parser.status
      result[:status] = encode_value(status)
    rescue
      response['Content-Type'] = 'application/json'
      response.body = {
        code: 101,
        msg: "success, but not parsed",
        data: result
      }.to_json
      return
    end

    [:created_on, :updated_on, :expires_on,
    :registrant_contacts, :admin_contacts, :technical_contacts,
    :nameservers].each do |contact_type|
      begin
        value = parser.send(contact_type)
        result[contact_type] = encode_value(value)
      rescue
        result[contact_type] = nil
      end
    end

    begin
      registrar = parser.registrar
      result[:registrar] = registrar ? encode_value(registrar.to_h.slice(:id, :name, :organization, :url)) : nil
    rescue
      result[:registrar] = nil
    end

    response['Content-Type'] = 'application/json'
    response.body = {
      code: 0,
      msg: "success",
      data: result      
    }.to_json

  rescue Timeout::Error
    response['Content-Type'] = 'application/json'
    response.body = {
      code: 102,
      msg: "timeout",
      data: nil
    }.to_json

  rescue Whois::WebInterfaceError, Whois::NoInterfaceError => e
    response['Content-Type'] = 'application/json'
    response.body = {
      code: 103,
      msg: "Service unavailable #{e.message}",
      data: {
        domain: domain,
        raw_data: "#{e.message}"
      }
    }.to_json

  rescue StandardError => e
    response['Content-Type'] = 'application/json'
    response.body = {
      code: 104,
      msg: "Other error #{e.class} - #{e.message}"
    }.to_json
  end
end
