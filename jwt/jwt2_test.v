module jwt

import encoding.hex
import crypto.ed25519

fn test_signing_method_eddsa() {
	mut h := signing_method_eddsa
	
	assert "EdDSA" == h.alg()
	assert 64 == h.sign_length()

	mut claims := map[string]JsonAny{}
	claims["aud"] = JsonAny("example.com")
	claims["iat"] = JsonAny("foo")

	pubkey, prikey := ed25519.generate_key()!

	token_string := h.sign[map[string]JsonAny](claims, prikey)!
	assert token_string.len > 0

	parsed := h.parse(token_string, pubkey)!

	claims2 := parsed.get_claims()!
	claims21 := claims2.as_map_of_strings()
	assert "example.com" == claims21["aud"]
	assert "foo" == claims21["iat"]
}

fn test_signing_method_ed25519() {
	mut h := signing_method_ed25519

	assert "ED25519" == h.alg()
	assert 64 == h.sign_length()

	mut claims := map[string]JsonAny{}
	claims["aud"] = JsonAny("example.com")
	claims["iat"] = JsonAny("foo")

	pubkey, prikey := ed25519.generate_key()!

	token_string := h.sign[map[string]JsonAny](claims, prikey)!
	assert token_string.len > 0

	parsed := h.parse(token_string, pubkey)!

	claims2 := parsed.get_claims()!
	claims21 := claims2.as_map_of_strings()
	assert "example.com" == claims21["aud"]
	assert "foo" == claims21["iat"]
}

fn test_signing_method_eddsa_check() {
    pub_key := "587ef3ea1a58aaf3e7b368b89fdcb29b0bc1dc03e18b82f243b887393e9caed1"
    pri_key := "414c119ae6958c5ccd7285c4894dbcd191e4942f0e14e42e8bc9631c10777b9a"
    token_str := "eyJhbGciOiJFRDI1NTE5IiwidHlwIjoiSldUIn0.eyJmb28iOiJiYXIifQ.ESuVzZq1cECrt9Od_gLPVG-_6uRP_8Nq-ajx6CtmlDqRJZqdejro2ilkqaQgSL-siE_3JMTUW7UwAorLaTyFCw"

	pri_key_buf := hex.decode(pri_key)!
	pub_key_buf := hex.decode(pub_key)!

	prikey := ed25519.new_key_from_seed(pri_key_buf)
	pubkey := ed25519.PublicKey(pub_key_buf)

	mut h := signing_method_ed25519

	mut claims := map[string]JsonAny{}
	claims["foo"] = JsonAny("bar")

	token_string := h.sign[map[string]JsonAny](claims, prikey)!
	assert token_string.len > 0

	parsed := h.parse(token_str, pubkey)!

	claims2 := parsed.get_claims()!
	claims21 := claims2.as_map_of_strings()
	assert "bar" == claims21["foo"]
}

fn test_signing_method_eddsa_check_with_pem_key() {
    pub_key := '-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAj/CWF9RnNKe/L0jHWHpUICXDowaNYLbj7Ck/wdzTvE4=
-----END PUBLIC KEY-----'
    pri_key := '-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIK3jWwBPmk1J4dynA3CjSfOLP9seazHZYZ6MCqCU+n0f
-----END PRIVATE KEY-----'
	token_str := "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJmb28iOiJiYXIifQ.AMI_8S4nuqBQ8Y7MLrU_iyDXDJcd651Y7eDR3AO98tfDGKkkp2MJj-yQoZzdbjeYrl3ocotlmor3Otwf1PUbCQ"

	prikey := parse_eddsa_privatekey_pem(pri_key)!
	pubkey := parse_eddsa_publickey_pem(pub_key)!

	mut h := signing_method_eddsa

	mut claims := map[string]JsonAny{}
	claims["foo"] = JsonAny("bar")

	token_string := h.sign[map[string]JsonAny](claims, prikey)!
	assert token_string.len > 0

	parsed := h.parse(token_str, pubkey)!

	claims2 := parsed.get_claims()!
	claims21 := claims2.as_map_of_strings()
	assert "bar" == claims21["foo"]
}
