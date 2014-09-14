{execFile} = require "child_process"
{createHash} = require "crypto"
{isBuffer} = Buffer

module.exports = class Authority
  constructor: (options={}) ->
    {@key, @certificate} = options


  certify: (input={}, callback) ->
    params = 
      "signing_certificate": @certificate
      "signing_key": @key
    params[param] = input[param] for param in @certifyParams
    Authority.createCertificate params, callback

  certifyParams: [
    "subject"
    "subject_key"
    "subject_public_key"
    "subject_signed_public_key"
    "started_at"
    "expires_at"
    "serial_number"
    "extensions"
  ]


  @createCertificate: (params, callback) =>
    callback ?= params.callback or ->

    for param in ["signing_key", "signing_certificate", "subject_key"]
      if isBuffer params[param]
        params[param] = params[param].toString("utf-8")

    if params["subject_signed_public_key"]?
      params["subject_signed_public_key"] = params["subject_signed_public_key"].replace("\r\n","").trim()

    params["subject"] = @convertSubjectToDistinguishedName params["subject"]

    params["extensions"] ?= []
    params["extensions"].push @makeBasicConstraintsFor params
    params["extensions"].push {name: "subjectKeyIdentifier", value: "hash", critical: false}
    params["extensions"].push {name: "authorityKeyIdentifier", value: "keyid:issuer", critical: false}

    params["serial_number"] ?= @makeSerialNumberFor(params)

    @execRuby "certify", params, (error, output) ->
      if error
        callback new Error error.toString().split("\n")[0].split("<main>':")[1].trim()
      else
        callback undefined,
          text: output["text"]
          fingerprint: output["fingerprint"]
          serialNumber: params["serial_number"]
          der: new Buffer output["base64_encoded_der"], "base64"
          pem: new Buffer output["pem"], "UTF-8"


  @convertSubjectToDistinguishedName: (subject) ->
    converted = {}
    for key, value of subject
      converted[@DISTINGUISHED_NAME_FIELDS[key]] = value
    converted

  @DISTINGUISHED_NAME_FIELDS =
    "common_name": "CN"
    "title": "title"
    "organization": "O"
    "organizational_unit": "OU"
    "business_category": "businessCategory"
    "email_address": "emailAddress"
    "street_address": "STREET"
    "location": "L"
    "region": "ST"
    "country_code": "C"
    "user_id": "UID"


  @makeSerialNumberFor: (params) ->
    hash = createHash("SHA1")
    hash.update JSON.stringify params["subject"]
    hash.update (new Date).toJSON()
    hash.update params["subject_signed_public_key"] if params["subject_signed_public_key"]?
    hash.digest "hex"


  @makeBasicConstraintsFor: (params) ->
    extension = {name: "basicConstraints", critical: true}
    extension.value = switch
      when params["certificate_authority"]?.pathlen?
        "CA:TRUE,pathlen:" + params["certificate_authority"].pathlen
      when params["certificate_authority"] is true
        "CA:TRUE"
      else
        "CA:FALSE"
    extension


  @execRuby: (script, params, callback) ->
    @locateRuby (error, ruby) =>
      return callback error if error?
      execFile ruby, ["#{__dirname}/#{script}.rb", JSON.stringify(params)], (error, stdout) ->
        output = JSON.parse(stdout) unless error?
        callback error, output


  @locateRuby: (callback) ->
    if @ruby?
      callback undefined, @ruby
    else
      execFile "/usr/bin/which", ["ruby"], (error, stdout) =>
        if error?.code is 1
          error new Error '''Can’t locate your copy of ruby. Please set Authority.ruby = "path/to/your/ruby"'''
        else
          @ruby = stdout.trim()
        callback error, @ruby
