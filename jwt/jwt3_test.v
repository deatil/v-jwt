module jwt

import crypto.ecdsa

fn test_signing_method_es256() {
	mut h := signing_method_es256
	assert "ES256" == h.alg()
	assert 64 == h.sign_length()

	mut claims := map[string]JsonAny{}
	claims["aud"] = JsonAny("example.com")
	claims["iat"] = JsonAny("foo")

	pubkey, prikey := ecdsa.generate_key(nid: .prime256v1)!

	token_string := h.sign[map[string]JsonAny](claims, prikey)!
	assert token_string.len > 0

	parsed := h.parse(token_string, pubkey)!

	claims2 := parsed.get_claims()!
	claims21 := claims2.as_map_of_strings()
	assert "example.com" == claims21["aud"]
	assert "foo" == claims21["iat"]
}

fn test_signing_method_es384() {
	mut h := signing_method_es384

	assert "ES384" == h.alg()
	assert 96 == h.sign_length()

	mut claims := map[string]JsonAny{}
	claims["aud"] = JsonAny("example.com")
	claims["iat"] = JsonAny("foo")

	pubkey, prikey := ecdsa.generate_key(nid: .secp384r1)!

	token_string := h.sign[map[string]JsonAny](claims, prikey)!
	assert token_string.len > 0

	parsed := h.parse(token_string, pubkey)!

	claims2 := parsed.get_claims()!
	claims21 := claims2.as_map_of_strings()
	assert "example.com" == claims21["aud"]
	assert "foo" == claims21["iat"]
}

fn test_signing_method_es512() {
	mut h := signing_method_es512

	assert "ES512" == h.alg()
	assert 132 == h.sign_length()

	mut claims := map[string]JsonAny{}
	claims["aud"] = JsonAny("example.com")
	claims["iat"] = JsonAny("foo")

	pubkey, prikey := ecdsa.generate_key(nid: .secp384r1)!

	token_string := h.sign[map[string]JsonAny](claims, prikey)!
	assert token_string.len > 0

	parsed := h.parse(token_string, pubkey)!

	claims2 := parsed.get_claims()!
	claims21 := claims2.as_map_of_strings()
	assert "example.com" == claims21["aud"]
	assert "foo" == claims21["iat"]
}

fn test_signing_method_es256k() {
	mut h := signing_method_es256k
	assert "ES256K" == h.alg()
	assert 64 == h.sign_length()

	mut claims := map[string]JsonAny{}
	claims["aud"] = JsonAny("example.com")
	claims["iat"] = JsonAny("foo")

	pubkey, prikey := ecdsa.generate_key(nid: .secp256k1)!

	token_string := h.sign[map[string]JsonAny](claims, prikey)!
	assert token_string.len > 0

	parsed := h.parse(token_string, pubkey)!

	claims2 := parsed.get_claims()!
	claims21 := claims2.as_map_of_strings()
	assert "example.com" == claims21["aud"]
	assert "foo" == claims21["iat"]
}

fn test_signing_method_es256_check() {
    pub_key := '-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETpIfMi7oTcpgtbeQ0kulzYlAKLQS
t1pfOGUHtHvce8MEssueOxCHWJKql/sJ+JrJSfqOu5AWlDqGqp77ZA7JCw==
-----END PUBLIC KEY-----'
    pri_key := '-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg/DkEwUlK8nWyB30J
RyxjU42bu//wSrGj2szLE/ybKMqgCgYIKoZIzj0DAQehRANCAAROkh8yLuhNymC1
t5DSS6XNiUAotBK3Wl84ZQe0e9x7wwSyy547EIdYkqqX+wn4mslJ+o67kBaUOoaq
nvtkDskL
-----END PRIVATE KEY-----'
	// token_str := "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIifQ.feG39E-bn8HXAKhzDZq7yEAPWYDhZlwTn3sePJnU9VrGMmwdXAIEyoOnrjreYlVM_Z4N13eK9-TmMTWyfKJtHQ"
	token_str := "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIifQ.MEUCIQDvO-42iKytRWzV8bxTz9xO0GjZiGKWIycBGvDxcZ2J6gIgURWb7Q3qGAD_iBbVupLcPJ1BwxKcWH5VRsAtnhQKn1Y"

	prikey := ecdsa.privkey_from_string(pri_key)!
	pubkey := ecdsa.pubkey_from_string(pub_key)!

	mut h := signing_method_es256

	mut claims := map[string]JsonAny{}
	claims["foo"] = JsonAny("bar")

	token_string := h.sign[map[string]JsonAny](claims, prikey)!
	assert token_string.len > 0

	parsed := h.parse(token_str, pubkey)!

	claims2 := parsed.get_claims()!
	claims21 := claims2.as_map_of_strings()
	assert "bar" == claims21["foo"]

	prikey.free()
	pubkey.free()
}
