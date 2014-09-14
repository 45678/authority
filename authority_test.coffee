{writeFileSync} = require "fs"
{assert} = require "nodeunit"
{isBuffer} = Buffer

assert.assert = (result, message) -> assert.strictEqual result, true, message
assert.equality = (a, b, message) -> assert.strictEqual a, b, message
assert.symmetry = (a, b, message) -> assert.deepEqual a, b, message

Authority = require "./authority.js"

ROOT_SUBJECT =
  "country_code": "CA"
  "organization": "Example Internet Authority"
  "common_name":  "Example Root CA"

HOST_SUBJECT =
  "country_code": "CA"
  "title":        "Members Only Website"
  "location":     "https://members.example.ca/"
  "common_name":  "members.example.ca"

PEER_SUBJECT =
  "common_name":  "Example Membership Certificate"
  "location":     "https://members.example.ca/"
  "country_code": "CA"

module.exports =
  "Authority can locate ruby": (test) ->
    Authority.locateRuby (error, ruby) ->
      test.assert /ruby$/.test ruby
      test.equality ruby, Authority.ruby
      test.done(error)


  "certificate provides hex encoded SHA1 fingerprint": (test) ->
    Authority.createCertificate
      "subject": HOST_SUBJECT
      "subject_key": HOST_KEY
      "started_at": "2012-01-01T00:00:00.000Z"
      "expires_at": "2013-01-01T00:00:00.000Z"
      "serial_number": "1"
      "callback": (error, certificate) ->
        test.equality certificate.fingerprint, "7a7956c6b2555fe0f81461167eca3fe541ed4448"
        test.done(error)


  "certificate provides serial number": (test) ->
    Authority.createCertificate
      "subject": HOST_SUBJECT
      "subject_key": HOST_KEY
      "started_at": "2012-01-01T00:00:00.000Z"
      "expires_at": "2013-01-01T00:00:00.000Z"
      "serial_number": "1"
      "callback": (error, certificate) ->
        test.equality certificate.serialNumber, "1"
        test.done(error)


  "serial number is automatically assigned when serial_number param is omitted": (test) ->
    Authority.createCertificate
      "subject": HOST_SUBJECT
      "subject_key": HOST_KEY
      "started_at": "2012-01-01T00:00:00.000Z"
      "expires_at": "2013-01-01T00:00:00.000Z"
      "callback": (error, certificate) ->
        test.equality certificate.serialNumber.constructor, String
        test.equality certificate.serialNumber.length, 40
        test.done(error)


  "certificate provides PEM and DER encoded binary forms": (test) ->
    Authority.createCertificate
      "subject": HOST_SUBJECT
      "subject_key": HOST_KEY
      "started_at": "2012-01-01T00:00:00.000Z"
      "expires_at": "2013-01-01T00:00:00.000Z"
      "callback": (error, certificate) ->
        test.assert isBuffer certificate.pem, "Missing PEM encoded bytes"
        test.assert certificate.pem.length isnt 0
        test.assert isBuffer certificate.der, "Missing DER encoded bytes"
        test.assert certificate.der.length isnt 0
        test.done(error)


  "accepts PEM encoded UTF-8 strings for key and certificate params": (test) ->
    Authority.createCertificate
      "subject": HOST_SUBJECT
      "subject_key": HOST_KEY
      "signing_certificate": ROOT_CERTIFICATE
      "signing_key": ROOT_KEY
      "serial_number": "1"
      "started_at": "2012-01-01T00:00:00.000Z"
      "expires_at": "2013-01-01T00:00:00.000Z"
      "callback": (error, certificate) ->
        test.equality certificate.fingerprint, "b41247b5ae3704312109971f5b4639cbe946ebcc"
        test.done(error)


  "accepts PEM encoded buffers for key and certificate params": (test) ->
    Authority.createCertificate
      "subject": HOST_SUBJECT
      "subject_key": new Buffer HOST_KEY, "UTF-8"
      "signing_certificate": new Buffer ROOT_CERTIFICATE, "UTF-8"
      "signing_key": new Buffer ROOT_KEY, "UTF-8"
      "serial_number": "1"
      "started_at": "2012-01-01T00:00:00.000Z"
      "expires_at": "2013-01-01T00:00:00.000Z"
      "callback": (error, certificate) ->
        test.equality certificate.fingerprint, "b41247b5ae3704312109971f5b4639cbe946ebcc"
        test.done(error)


  "create self signed root authority certificate": (test) ->
    Authority.createCertificate
      "certificate_authority": true
      "subject": ROOT_SUBJECT
      "subject_key": ROOT_KEY
      "started_at": "2012-01-01T00:00:00.000Z"
      "expires_at": "2013-01-01T00:00:00.000Z"
      "serial_number": "1"
      "callback": (error, certificate) ->
        test.equality certificate.fingerprint, "138d2afb4ea1596562c17b4a2da233232cc8c283"
        test.done(error)


  "create a self signed host certificate": (test) ->
    Authority.createCertificate
      "subject": HOST_SUBJECT
      "subject_key": HOST_KEY
      "started_at": "2012-01-01T00:00:00.000Z"
      "expires_at": "2013-01-01T00:00:00.000Z"
      "serial_number": "1"
      "callback": (error, certificate) ->
        test.equality certificate.fingerprint, "7a7956c6b2555fe0f81461167eca3fe541ed4448"
        test.done(error)


  "create a host certificate issued by the root authority": (test) ->
    Authority.createCertificate
      "subject": HOST_SUBJECT
      "subject_key": HOST_KEY
      "signing_certificate": ROOT_CERTIFICATE
      "signing_key": ROOT_KEY
      "started_at": "2012-01-01T00:00:00.000Z"
      "expires_at": "2013-01-01T00:00:00.000Z"
      "serial_number": "1"
      "callback": (error, certificate) ->
        test.equality certificate.fingerprint, "b41247b5ae3704312109971f5b4639cbe946ebcc"
        test.done(error)


  "create a peer certificate with a signed public key issued by the root authority": (test) ->
    Authority.createCertificate
      "subject": PEER_SUBJECT
      "subject_signed_public_key": PEER_SIGNED_PUBLIC_KEY
      "signing_certificate": ROOT_CERTIFICATE
      "signing_key": ROOT_KEY
      "started_at": "2012-01-01T00:00:00.000Z"
      "expires_at": "2013-01-01T00:00:00.000Z"
      "serial_number": "1"
      "callback": (error, certificate) ->
        test.equality certificate.fingerprint, "7acba8577b8d25d002dbcf9dcccca78ce870a2d5"
        test.done(error)


  "can’t create a peer certificate with a malformed signed public key": (test) ->
    Authority.createCertificate
      "subject": PEER_SUBJECT
      "subject_signed_public_key": "NOT A VALID SPKI STRUCTURE"
      "signing_key": ROOT_KEY
      "signing_certificate": ROOT_CERTIFICATE
      "started_at": "2012-01-01T00:00:00.000Z"
      "expires_at": "2013-01-01T00:00:00.000Z"
      "callback": (error, certificate) ->
        test.equality error.toString(), "Error: Subject’s signed public key wasn’t a valid SPKI structure. (RuntimeError)"
        test.equality certificate, undefined
        test.done()


ROOT_KEY = """
  -----BEGIN RSA PRIVATE KEY-----
  MIIEowIBAAKCAQEA070Lfnq7VONdhykYGMqUWfPhvd5kRfdyJCfVdTYmNi9f8B1C
  aS6c9FnDT5HEu29MhiVjLwx+hKz06GXLyUvyJQd95/nc1Tx0qehb06GVVzHBE9dv
  GIP1ddBh9wkKQ+TVNhJ3zmRdnhmVrOzJhh5R+Pbt4TkgTUD+uNYQMRlCQbn23ezq
  1ENxjrcqdnpU8WbZ14DsmWL5i0E6eIQ8+YXfhu1Z15Q5uSwT/r/poSS7ZWzXsX3U
  3CAgCJraxJ3M6EPp3+XjC5bT/gOkukBwz6dzzlgMuB3ov9LlGwA/drNYQ2Gefkxv
  kNMG4RJBDdSSJ0f1ozdteOxaBaS7F2DkldQFpwIDAQABAoIBAFc+wgmvkJj9xn/2
  0tMERfR6pT2S8UZTG1kCgNX3Je+VvbY2mDK23j1g7zVOHv4Mcj+kECZGw6rviUpp
  B3s+K9xOJfb74Z6Ldpa8A3pETkDLY39FeaVkWjPdVUBxHSW0mJXbLjqA6IJIkH/c
  YX096RDozkPLQiAS8+I9chaJDd/+e8XgaoZ9wfejFsWIcLpLJpXJgiHt3+jgoI/i
  dfQUwL9JAIHuaV3GRbfZVUgrMNXgH+ae26omNc3FkH2VyhhrCHAk8oh1d8SgU5+n
  K5WguH8PEkSPn10jqj8rlfE5CeF7gF3TIdVuVpWBBc+kSoyhIB/LSCRf3rWSRI42
  hpW1GWECgYEA/YkQ7HtBxxhg6S92apUlMnUI0Ivb9Brd+Oew4hLCk7926ERTTwOR
  MIvUt5Ut0yObQap/uAkxBDO05IdALp/vhZ84xVtAfqgquCXwS2jLoVTQGCTTwcOA
  X6OSKWMif74jksH2VnRonBYxsSE8BLhNwFiDQVfBr4l3VKZQbkHH1dsCgYEA1cv3
  Gk4omw2qt/ZKWZe3dsMNIxyBgV/ZcKhr2mc/x9DtGSe4yiJTc5BamDpMcinEo2zS
  BwxT3QkokQAkBTcaZ0GSvGju7CmX7SX59eFM6xZMN+Mrebh0RrguN8eotMaQ4log
  ojm5+UxqrKlX4KjsNVvjJ//fXWrWqABWACDlZyUCgYBPDfUj987r2LMnIrCGzVia
  4hlMhb+g3tvF5+CkrXrUfQgDpoJfido0y/UZBUATrO+VSyel59/L0p+d/npJz37t
  KFeYWjrDA4bGgrXpnZSZCowUay9IJMCbkbJai1nPgScwdKBuFsAjo1v9QkKnqhw8
  VJ0gu89d/7wgvfcoWgSIrwKBgFPskv1SfQIQpVk9ZwYwViZafsevou6kL3jXxC6h
  pRnM26WqQBGo09Vjbwyepe+SkcwNJYz6u9jihXgV9A3QCZ9K0E0Ba/hsg2TmKW7p
  mAYYZKbzl9daHtq75fijeYgtAia4dmL4Ahbodl98wjBAXyi6/zpuaMIE9GpSZ2/5
  edO5AoGBAMVx1WZhS11Qzsi+4YcrUMt0YBzSb72uvoNVdQGY/KKqDL3NdIR+iR2Q
  1xz302RbnF6cEjrzqTYtfpyOBdlufWhQ0F4hk5E6hmw7MDJpVAP2YJ+CsTdPID6X
  cniO2buxYlRU5DxaZ4kzme4aixFihoJvt4g+KWim/R7tjMYZmX9D
  -----END RSA PRIVATE KEY-----
"""

ROOT_CERTIFICATE = """
  -----BEGIN CERTIFICATE-----
  MIIDZjCCAk6gAwIBAgIBATANBgkqhkiG9w0BAQsFADBMMQswCQYDVQQGEwJDQTEj
  MCEGA1UECgwaRXhhbXBsZSBJbnRlcm5ldCBBdXRob3JpdHkxGDAWBgNVBAMMD0V4
  YW1wbGUgUm9vdCBDQTAeFw0xMjAxMDEwNTAwMDBaFw0xMzAxMDEwNTAwMDBaMEwx
  CzAJBgNVBAYTAkNBMSMwIQYDVQQKDBpFeGFtcGxlIEludGVybmV0IEF1dGhvcml0
  eTEYMBYGA1UEAwwPRXhhbXBsZSBSb290IENBMIIBIjANBgkqhkiG9w0BAQEFAAOC
  AQ8AMIIBCgKCAQEA070Lfnq7VONdhykYGMqUWfPhvd5kRfdyJCfVdTYmNi9f8B1C
  aS6c9FnDT5HEu29MhiVjLwx+hKz06GXLyUvyJQd95/nc1Tx0qehb06GVVzHBE9dv
  GIP1ddBh9wkKQ+TVNhJ3zmRdnhmVrOzJhh5R+Pbt4TkgTUD+uNYQMRlCQbn23ezq
  1ENxjrcqdnpU8WbZ14DsmWL5i0E6eIQ8+YXfhu1Z15Q5uSwT/r/poSS7ZWzXsX3U
  3CAgCJraxJ3M6EPp3+XjC5bT/gOkukBwz6dzzlgMuB3ov9LlGwA/drNYQ2Gefkxv
  kNMG4RJBDdSSJ0f1ozdteOxaBaS7F2DkldQFpwIDAQABo1MwUTAPBgNVHRMBAf8E
  BTADAQH/MB0GA1UdDgQWBBSSEv09t8qQtzdbhgdP86tOIs52fTAfBgNVHSMEGDAW
  gBSSEv09t8qQtzdbhgdP86tOIs52fTANBgkqhkiG9w0BAQsFAAOCAQEAySI6mcXh
  P2s9IiX1JWro3IWmyJMH1ZvdKIq4f6Y2eR/pn0ILcvGhv0t+7bGa85s5b79hZC1h
  a0Qu+wWwfv3RZAx2afNY94mAXdtToIQ/zbopLQOJZZDNFP+ehjlE8Vqu24r9mYKF
  GFD3FBRIqc9dk6zA0/GyPg1ZMYriZ2juk/Z9r3Sny3MB4pSjqYs4N9Uf49p8AtnA
  yljN+Aib24/xJ9hOoQEk+XGz0B0DgMmux1PFzxtGjbAr1l614k1AtIWBYswYAR4s
  LRW6QJicX/nj6vQU3UwUiB6OxdzMs23BVSw3n3qXh78h4XDYK1A1ELV8OS6tF+bp
  Srb5hUzJ1Wa1vg==
  -----END CERTIFICATE-----
"""

HOST_KEY = """
  -----BEGIN RSA PRIVATE KEY-----
  MIIEowIBAAKCAQEAn5jaXI8nfTp3k4l1qdQzK5El6kmNjT8pe0siSywLIrdMygaI
  35gkO0nyHn5ORRJoLVv03ydI9gMVUwAjTHgHAzyP8wUJVquhZpF50+f9V+OwWfEp
  dHTtlsZTlKeKvcfHIHsiTfu61tejVQ2CAUaPeK2QGO6JefLOGz4WCQ983Bbg4ZKE
  MdwQX1b8bAgcJjibedUl6zVsjtr0dttJ41oijpKQluvLpIdgIDx4TyUaBm2wrqUs
  DVGfSDGo/nF33NwmAdjffVMi2rbK0DrFAyA8md9YbTRO+98fK4N/QVlJSvw7JG0k
  jRHMl9tnrzZcTqam/pwJHbh7fT09yOkgQHn4swIDAQABAoIBAA65zNQjhVJBtczQ
  LyInaT1I3EW82anBvTMaIKTtAG4ImbY+Why/bgBmd0enAdPPufsNdA+vEUVZzXrm
  FVu163e5+9JBkbYEihTrsWEDE9YrNRdncBrFuzJhRE8AEoYmS9JMakLlyjyOkwyC
  /Y7ekthgs14JjHfLFode+CuH2U55TKNZFMWn15z3rzbHoAKy9eGqsd0nbGzxS7PI
  qhGQy15HdPs04zpZgSGlddYoeTh1fBbl8WY9Jc21eBAx4bBBnZ+uPe4Mjx7NhUA6
  UcrQDxZat++X5o30nFiUrNvzsjSWecTTTb+UzY1ZdSSlOL0fHEW3tAqrTGVr2bl7
  kP/Ol+ECgYEAy2m2U9XBbYGzeEfTygH3KWFds2LMEEwYsKBgkl5NxasNZ/uNWkWk
  9bVadGwAtIhkwaI4TZohPDAdqgsd6ba/F2neH+QvCMO4H6ZXihjXIJhJ/f5IohYW
  VeIlk7jd6ISMKo1uQhPFgV8Ukw4PJztabFz/i3qsRKbFTMOqWgkl2hECgYEAyNtR
  J9G6JKxOSb3jLGhKDrVrp+GkRCgZfX6pNP21fn/pxyp3h3WhMwlx5DygFVrd8MSf
  qIy8eNFozXmdj9YhNf67eVogMy3e9Rdc8Un4FZiZyUDTHWNM/GB7HNOwFBgoazdm
  aXFbp+MBZsQFk7jVjBdYmHYofcLFtGzIzvazQoMCgYB4TYUv//PuOA9Uy+ZOSutK
  5fLs7TmTSe4wSCnVZ0DH72p2XSg0g4wUZbWhtV6VZzVv7+ksvEN7vVlOAFUorJRH
  3K0qX2IR5O84iMCtRBO3i1n3hjSe6EE9egqPW36izgG4CP10xwzAfuNENcRwh4Hr
  JPVeIKdR0vBNfkt6BH8GgQKBgBrmTGshymUo8l8r4CXNXcW0hFN6g65hFHDbKrwf
  ElR7uwpiZJmupkUYiblAaUwS3FBndN504rTnjrqeA/0Ed3QsxlzNNizEguyeEWN7
  PY9e3ZG3bc6swt216icFLrqyNY+OXtfWR6knXMOvkvOiuG7HnaTlhiy5jhLI0ufs
  4DsTAoGBAKtwiL4gUfiFFht5UfrbNv4A+iTylbJAYl8LFUwF9MH2apRH2hOKqdhx
  bRv44heWiSKlzmW8ebxQpKcw38GicV/Q5UBUw9RryW/UehaXt2f8lYlcP+SiUqaR
  IjoaO2Cay1Fj2BG38gRQ9EW1Y8/AmZMUuBGSIRUhlaRHJK6Opqna
  -----END RSA PRIVATE KEY-----
"""

PEER_PUBLIC_KEY = """
  -----BEGIN RSA PUBLIC KEY-----
  MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo2pqVANsVqz+eeW+cMSX
  dGfqCjZLCG8+YGoaLcRZrzoXzmMyRnubAGRjReeUE8Zu3wTrqx8+4Nw+FpoANza6
  R/fYrmlk6PonVL96FCy5G8rvOk0Z/a9HFEFqG53smiEtZCXMFj8pCTF/YChlPkoh
  d+2Wif5DkDxJTd00x3nS70fe/BKuIDHt0LwXKyHWw1KBHpjBhndC+VoB6hEVpa64
  DDztiSJYeG54wt0jcskt7AE63G9ZzveybLfPfRC6Al4d5Bahd/OH+rntn5peBBmy
  T2IX9W7aq+JmhCKG2N31ObMlcSSh3BLEdm27DPoUs/KpervLMbN2q9mB8edywjIT
  QQIDAQAB
  -----END RSA PUBLIC KEY-----
"""

PEER_SIGNED_PUBLIC_KEY = """
  MIICQTCCASkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCjampUA2xWrP555b5wxJd0Z+oKNksIbz5gahotxFmvOhfOYzJGe5sAZGNF55QTxm7fBOurHz7g3D4WmgA3NrpH99iuaWTo+idUv3oULLkbyu86TRn9r0cUQWobneyaIS1kJcwWPykJMX9gKGU+SiF37ZaJ/kOQPElN3TTHedLvR978Eq4gMe3QvBcrIdbDUoEemMGGd0L5WgHqERWlrrgMPO2JIlh4bnjC3SNyyS3sATrcb1nO97Jst899ELoCXh3kFqF384f6ue2fml4EGbJPYhf1btqr4maEIobY3fU5syVxJKHcEsR2bbsM+hSz8ql6u8sxs3ar2YHx53LCMhNBAgMBAAEWAQAwDQYJKoZIhvcNAQEEBQADggEBAAC3TYUrPVK5t0Cfet39txHEEVtCyI8ZfDJzPQAQLaX7/L8QqjjpeGsPdAgWMJ7PFjohLT0LpSKONlAbEQ4f3Aj8Oa4t+bSvTCzZb3LEANFjn9NUzMZAHW5Ie2A+TG7t0nqHiCFC+5tCTN3mHnJM4bzxHBQ44dgxCp0EDzzaJOpZAlokxzj//YfuC7EoDuRAsfTSnznjQVT7Jx/m48Pun9tOGMCJ9MHTVfw9bqqNU0TqOi5/0ulPAc1G2dKpvEKN5BJU482pWNG5zSxmyA4d2JSLIVtwHYETzPd404bC6khiXIwMS3ajnQIEn25RLPdOdrbg7RzcEP4a49gQsSzt3rE=
"""
