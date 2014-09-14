# encoding: UTF-8
require "base64"
require "json"
require "openssl"

params = JSON.parse ARGV[0]

subject = params["subject"].keys.inject(OpenSSL::X509::Name.new) do |subject, key|
  subject.add_entry key, params["subject"][key]
end

public_key = case
when params["subject_key"]
  subject_key = OpenSSL::PKey.read params["subject_key"]
  subject_key.public_key
when params["subject_signed_public_key"]
  begin
    subject_signed_public_key = OpenSSL::Netscape::SPKI.new params["subject_signed_public_key"]
  rescue OpenSSL::Netscape::SPKIError
    raise "Subject’s signed public key wasn’t a valid SPKI structure."
  end
  if subject_signed_public_key.verify subject_signed_public_key.public_key
    subject_signed_public_key.public_key
  else
    raise "Subject’s signed public key didn’t pass verification."
  end
else
  raise "Subject’s public key information wasn’t supplied."
end

if params["signing_key"]
  signing_key = OpenSSL::PKey.read params["signing_key"]
else
  signing_key = subject_key
end

if params["signing_certificate"]
  signing_certificate = OpenSSL::X509::Certificate.new params["signing_certificate"]
  issuer = signing_certificate.subject
else
  signing_certificate = nil
  issuer = subject
end

certificate = OpenSSL::X509::Certificate.new
certificate.subject = subject
certificate.public_key = public_key
certificate.issuer = issuer
certificate.serial = params["serial_number"].to_i(16)
certificate.version = 2 # This actually means version 3 because version 1 is 0. Ridiculous.
certificate.not_before = Time.new params["started_at"]
certificate.not_after = Time.new params["expires_at"]

if params["extensions"]
  factory = OpenSSL::X509::ExtensionFactory.new
  factory.subject_certificate = certificate
  factory.issuer_certificate = signing_certificate.nil? ? certificate : signing_certificate
  params["extensions"].each do |attributes|
    arguments = attributes["name"], attributes["value"], attributes["critical"]
    certificate.add_extension factory.create_extension(*arguments)
  end
end

certificate.sign signing_key, OpenSSL::Digest::SHA256.new

output = {
  "pem" => certificate.to_pem,
  "base64_encoded_der" => Base64.encode64(certificate.to_der),
  "fingerprint" => OpenSSL::Digest::SHA1.hexdigest(certificate.to_der),
  "text" => certificate.to_text,
  "public_key" => {
    "pem" => public_key.to_pem,
    "base64_encoded_der" => Base64.encode64(public_key.to_der),
    "fingerprint" => OpenSSL::Digest::SHA1.hexdigest(public_key.to_der)
  }
}

puts output.to_json
