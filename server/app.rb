require 'sinatra'
require 'whois'
require 'whois-parser'

class MyWhoisApp < Sinatra::Base
  @@whois_client = Whois::Client.new

  get '/whois/:domain' do
    domain = params['domain']
    begin
      response = @@whois_client.lookup(domain)
      whois_server_host = response.server.host
      content_type :json

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
        raw_data: encode_value(response.content)
      }

      begin
        parser = response.parser
        status = parser.status
        result[:status] = encode_value(status)
      rescue
        return {
          code: 101,
          msg: "success, but not parsed",
          data: result
        }.to_json
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

      {
        code: 0,
        msg: "success",
        data: result      
      }.to_json

    rescue Timeout::Error
      {
        code: 102,
        msg: "timeout",
        data: nil
      }.to_json

    rescue Whois::WebInterfaceError, Whois::NoInterfaceError => e
      {
        code: 103,
        msg: "服务不可用 #{e.message}",
        data: {
          domain: domain,
          raw_data: "#{e.message}"
        }
      }.to_json

    rescue StandardError => e
      {
        code: 104,
        msg: "其他错误 #{e.class} - #{e.message}"
      }.to_json
    end
  end
  
end

