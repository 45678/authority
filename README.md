# Authority
_Make certificates in Node
with CoffeeScript (or any old ECMAScript)
using OpenSSL
via Ruby._

[Authority](https://github.com/45678/authority) generates [X.509 public key certificates](https://en.wikipedia.org/wiki/X.509) that can be used to:

- Verify the identity of a host on the internet.
- Verify the identity of a peer on the internet.
- Issue additional certificates.

For example, here is a script to make a basic self-signed certificate for an internet mail service:

    #!/usr/bin/env coffee

    {readFileSync, writeFileSync} = require "fs"

    Authority = require "authority"

    Authority.createCertificate
      "subject":
        "common_name":   "mail.example.org"
        "title":         "Example Mail Service"
        "email_address": "postmaster@example.org"
        "country_code":  "CA"

      "subject_key": readFileSync "mail.example.org.private.key"

      "started_at": (new Date).toJSON()
      "expires_at": "2020-01-01T00:00:01.000Z"

      "callback": (error, certificate) ->
        throw error if error
        writeFileSync "mail.example.org.crt", certificate.pem


# Start

Run `npm install 45678/authority.git` to get the module. Require it in your program like so:

    Authority = require "authority"

You’ll also need a copy of `ruby` installed on your computer. Authority employs the [OpenSSL bindings](http://www.ruby-doc.org/stdlib-1.9.3/libdoc/openssl/rdoc/OpenSSL) in [Ruby](http://ruby-lang.org/) to construct certificates because [Node](http://nodejs.org/) didn’t have built-in support for that kind of thing when this was written. Authority will run `/usr/bin/which ruby` to locate your `ruby` executable. If that doesn’t work, or if you just enjoy being explicit, you can set the path manually with:

    Authority.ruby = "/path/to/your/ruby"

# Input

`Authority.createCertificate(params, callback)` accepts the following named `params`:

`subject` defines the distinguished name of the subject of the certificate. Authority accepts the following distinguished name attributes: `common_name`, `title`, `organization`, `organizational_unit`, `business_category`, `email_address`, `street_address` `location`, `region`, `country_code` and `user_id`. The `common_name` attribute is the only one that is required.

`subject_key` is a PEM encoded RSA key that belongs to the subject of the certificate. The public key component of this key defines the public key information section of the certificate. You can pass this parameter as a `Buffer` or a `String`. This parameter is not required when you supply a `signed_public_key` and a `signing_key`.

`signed_public_key` is an [SPKAC/Netscape SPKI](http://en.wikipedia.org/wiki/SPKAC) structure that might have been generated via `openssl -spkac ...` or the `<keygen>` element in HTML. The public key component of this key becomes the public key information section of the certificate. You can only pass this parameter as a `String`.

`signing_certificate` is a PEM encoded X.509 certificate the belongs to the authority that is issuing the certificate. The subject of the signing certificate becomes the issuer of the created certificate. You can pass this parameter as a `Buffer` or a `String`. This parameter isn’t required when you’re creating self-signed certificate.

`signing_key` is a PEM encoded RSA key that belongs to the authority that is issuing the certificate. You can pass this parameter as a `Buffer` or a `String`. If you don’t supply a `signing_key` the certificate will be signed with the
`subject_key` producing a self-signed certificate.

The `started_at` and `expires_at` parameters define the validity period of the certificate. `started_at` defines the instant in time when the certificate comes into effect. `expires_at` defines the instant in time when the certificate expires. These parameters should be instances of `Date`. Both are always required.

`serial_number` defines the serial number of the certificate. A unique serial number in the form of a SHA1 hash is generated automatically if you omit this parameter.

`certificate_authority` specifies whether or not the certificate may be used to issue additional certificates. This parameter is optional. By default new certificates will have their basic constraints set to `CA:FALSE` to indicate that they may not be used to issue certificates under the authority of the issuer. Pass `true` or `{pathlen:0}`, `{pathlen:1}`, etc., to bless the certificate with the authoring capabilities that you require.

`callback` is a function that will be called when the certificate is ready (or an error occurs). You can pass your callback as a member of the `params` argument or you can pass it separately as the second argument in the form  `Authority.createCertificate(params, callback)`.

# Ouput

When `Authority.createCertificate` is finished your `callback` function will receive a `certificate` as its second argument. Each `certificate` has the following members:

`certificate.pem` is a `Buffer` that contains a PEM encoded binary copy of the certificate. Use this format if you’re saving your certificate to the file system. Or call `certificate.pem.toString()` to get a UTF-8 representation that you can easily save in a database.

`certificate.der` is a `Buffer` that contains a DER encoded binary copy of the certificate. Use this format if you are sending an `"application/x-509-user-cert"` to a web browser.

`certificate.fingerprint` is a SHA1 hex digest that uniquely identifies the certificate.

`certificate.serialNumber` is the serial number of the certificate.


# Using authority to certify a signed public key like it’s fucking 1996

Authority instances make it convenient to certify signed public keys posted
from Mozilla, Opera and Webkit (excluding Mobile Safari, unfortunately). That
means you can perform secure public key exchange on the web without too much
hassle (except that the human interface is unbearable, unfortunately).

    Authority = require "authority"
    Express   = require "express"
    HTTPS     = require "https"

    {readFileSync} = require "fs"

    club = new Authority
      cert: readFileSync "example.org.crt"
      key:  readFileSync "example.org.private.key"

    httpsOptions =
      ca:   club.certificate
      cert: club.certificate
      key:  club.key
      requestCert: true
      rejectUnauthorized: false

    (HTTPS.createServer httpsOptions, app = new Express).listen("0443")

    app.get "/members/only", (request, response, next) ->
      if request.client.authorized
        response.statusCode = 200
        response.setHeader "Content-Type", "text/plain"
        response.end "’Sup friendly member?"
      else
        response.redirect 303, "/membership/form"

    app.get "/membership/form", (request, response, next) ->
      response.statusCode = 200
      response.setHeader "Content-Type", "text/html"
      response.end """
        <form method="post" action="/membership">
          <input placeholder="Your Name" type="text" name="common_name">
          <p>
            A <keygen name="signed_public_key">-bit RSA key pair will be
            added to your Keychain when you start your membership.
          </p>
          <button>Start your membership</button>
        </form>
      """

    app.post "/membership", (request, response, next) ->
      club.certify
        "common_name":       request.params["common_name"]
        "signed_public_key": request.params["signed_public_key"]
        callback: (error, certificate) ->
          response.statusCode = 201
          response.setHeader "Connection", "close"
          response.setHeader "Content-Type", "application/x-x509-user-cert"
          response.end certificate.der


# Recommended Reading

[Establishing Identity Without Certification Authorities](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.31.7263&rep=rep1&type=pdf)
by Carl Ellison. Published at the _6th USENIX Security Symposium_ in 1996.

# Constraints

- Authority doesn’t create RSA keys. Generate them yourself with `openssl genrsa -out my.private.key 2048` or a similar command.
- Authority has no support for X.509 certificate signing requests.
- Authority doesn’t provide methods to read-or-write certificates to-or-from the file system.
- The bundled Ruby script only accepts JSON arguments.
