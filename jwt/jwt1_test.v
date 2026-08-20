module jwt

import encoding.hex

fn test_signing_method_hs256() {
	mut h := signing_method_hs256.new()

	assert "HS256" == h.alg()
	assert 32 == h.sign_length()

	mut claims := map[string]string{}
	claims["aud"] = "example.com"
	claims["iat"] = "foo"

	key := "test-key"

	token_string := h.sign[map[string]string](claims, key.bytes())!
	assert token_string.len > 0

	parsed := h.parse(token_string, key.bytes())!

	headers := parsed.get_headers_t[map[string]string]()!
	assert "JWT" == headers["typ"]
	assert "HS256" == headers["alg"]

	claims2 := parsed.get_claims()!
	claims21 := claims2.as_map_of_strings()
	assert "example.com" == claims21["aud"]
	assert "foo" == claims21["iat"]
}

fn test_signing_method_hs384() {
	mut h := signing_method_hs384.new()

	assert "HS384" == h.alg()
	assert 48 == h.sign_length()

	mut claims := map[string]string{}
	claims["aud"] = "example.com"
	claims["iat"] = "foo"

	key := "test-key"

	token_string := h.sign[map[string]string](claims, key.bytes())!
	assert token_string.len > 0

	parsed := h.parse(token_string, key.bytes())!

	claims2 := parsed.get_claims()!
	claims21 := claims2.as_map_of_strings()
	assert "example.com" == claims21["aud"]
	assert "foo" == claims21["iat"]
}

fn test_signing_method_hs512() {
	mut h := signing_method_hs512.new()

	assert "HS512" == h.alg()
	assert 64 == h.sign_length()

	mut claims := map[string]string{}
	claims["aud"] = "example.com"
	claims["iat"] = "foo"

	key := "test-key"

	token_string := h.sign[map[string]string](claims, key.bytes())!
	assert token_string.len > 0

	parsed := h.parse(token_string, key.bytes())!

	claims2 := parsed.get_claims()!
	claims21 := claims2.as_map_of_strings()
	assert "example.com" == claims21["aud"]
	assert "foo" == claims21["iat"]
}

fn test_signing_method_hs224() {
	mut h := signing_method_hs224.new()

	assert "HS224" == h.alg()
	assert 28 == h.sign_length()

	mut claims := map[string]string{}
	claims["aud"] = "example.com"
	claims["iat"] = "foo"

	key := "test-key"

	token_string := h.sign[map[string]string](claims, key.bytes())!
	assert token_string.len > 0

	parsed := h.parse(token_string, key.bytes())!

	claims2 := parsed.get_claims()!
	claims21 := claims2.as_map_of_strings()
	assert "example.com" == claims21["aud"]
	assert "foo" == claims21["iat"]
}

fn test_signing_method_hsha1() {
	mut h := signing_method_hsha1.new()

	assert "HSHA1" == h.alg()
	assert 20 == h.sign_length()

	mut claims := map[string]string{}
	claims["aud"] = "example.com"
	claims["iat"] = "foo"

	key := "test-key"

	token_string := h.sign[map[string]string](claims, key.bytes())!
	assert token_string.len > 0

	parsed := h.parse(token_string, key.bytes())!

	claims2 := parsed.get_claims()!
	claims21 := claims2.as_map_of_strings()
	assert "example.com" == claims21["aud"]
	assert "foo" == claims21["iat"]
}

fn test_signing_method_hmd5() {
	mut h := signing_method_hmd5.new()

	assert "HMD5" == h.alg()
	assert 16 == h.sign_length()

	mut claims := map[string]string{}
	claims["aud"] = "example.com"
	claims["iat"] = "foo"

	key := "test-key"

	token_string := h.sign[map[string]string](claims, key.bytes())!
	assert token_string.len > 0

	parsed := h.parse(token_string, key.bytes())!

	claims2 := parsed.get_claims()!
	claims21 := claims2.as_map_of_strings()
	assert "example.com" == claims21["aud"]
	assert "foo" == claims21["iat"]
}

fn test_signing_method_none() {
	mut h := signing_method_none.new()

	assert "none" == h.alg()
	assert 0 == h.sign_length()

	mut claims := map[string]string{}
	claims["aud"] = "example.com"
	claims["iat"] = "foo"

	key := ""

	token_string := h.sign[map[string]string](claims, key.bytes())!
	assert token_string.len > 0

	parsed := h.parse(token_string, key.bytes())!

	claims2 := parsed.get_claims()!
	claims21 := claims2.as_map_of_strings()
	assert "example.com" == claims21["aud"]
	assert "foo" == claims21["iat"]
}

fn test_signing_method_hs256_check() {
	key := "0323354b2b0fa5bc837e0665777ba68f5ab328e6f054c928a90f84b2d2502ebfd3fb5a92d20647ef968ab4c377623d223d2e2172052e4f08c0cd9af567d080a3"
	token_str := "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	key_bytes := hex.decode(key)!

	mut h := signing_method_hs256.new()

	mut claims := map[string]JsonAny{}
	claims["iss"] = JsonAny("joe")
	claims["exp"] = JsonAny(1300819380)
	claims["http://example.com/is_root"] = JsonAny(true)

	token_string := h.sign[map[string]JsonAny](claims, key_bytes)!
	assert token_string.len > 0

	parsed := h.parse(token_str, key_bytes)!

	claims2 := parsed.get_claims()!
	claims21 := claims2.as_map_of_strings()
	assert "joe" == claims21["iss"]
}

fn test_signing_method_hs384_check() {
	key := "0323354b2b0fa5bc837e0665777ba68f5ab328e6f054c928a90f84b2d2502ebfd3fb5a92d20647ef968ab4c377623d223d2e2172052e4f08c0cd9af567d080a3"
	token_str := "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJleHAiOjEuMzAwODE5MzhlKzA5LCJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZSwiaXNzIjoiam9lIn0.KWZEuOD5lbBxZ34g7F-SlVLAQ_r5KApWNWlZIIMyQVz5Zs58a7XdNzj5_0EcNoOy"

	key_bytes := hex.decode(key)!

	mut h := signing_method_hs384.new()

	mut claims := map[string]JsonAny{}
	claims["iss"] = JsonAny("joe")
	claims["exp"] = JsonAny(1300819380)
	claims["http://example.com/is_root"] = JsonAny(true)

	token_string := h.sign[map[string]JsonAny](claims, key_bytes)!
	assert token_string.len > 0

	parsed := h.parse(token_str, key_bytes)!

	claims2 := parsed.get_claims()!
	claims21 := claims2.as_map_of_strings()
	assert "joe" == claims21["iss"]
}

fn test_signing_method_hs512_check() {
	key := "0323354b2b0fa5bc837e0665777ba68f5ab328e6f054c928a90f84b2d2502ebfd3fb5a92d20647ef968ab4c377623d223d2e2172052e4f08c0cd9af567d080a3"
	token_str := "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjEuMzAwODE5MzhlKzA5LCJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZSwiaXNzIjoiam9lIn0.CN7YijRX6Aw1n2jyI2Id1w90ja-DEMYiWixhYCyHnrZ1VfJRaFQz1bEbjjA5Fn4CLYaUG432dEYmSbS4Saokmw"

	key_bytes := hex.decode(key)!

	mut h := signing_method_hs512.new()

	mut claims := map[string]JsonAny{}
	claims["iss"] = JsonAny("joe")
	claims["exp"] = JsonAny(1300819380)
	claims["http://example.com/is_root"] = JsonAny(true)

	token_string := h.sign[map[string]JsonAny](claims, key_bytes)!
	assert token_string.len > 0

	parsed := h.parse(token_str, key_bytes)!

	claims2 := parsed.get_claims()!
	claims21 := claims2.as_map_of_strings()
	assert "joe" == claims21["iss"]
}

fn test_signing_method_none_check() {
	key_bytes := "".bytes()
	token_str := "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."

	mut h := signing_method_none.new()

	mut claims := map[string]JsonAny{}
	claims["iss"] = JsonAny("joe")
	claims["exp"] = JsonAny(1300819380)
	claims["http://example.com/is_root"] = JsonAny(true)

	token_string := h.sign[map[string]JsonAny](claims, key_bytes)!
	assert token_string.len > 0

	parsed := h.parse(token_str, key_bytes)!

	claims2 := parsed.get_claims()!
	claims21 := claims2.as_map_of_strings()
	assert "joe" == claims21["iss"]
}

fn test_signing_method_blake2b() {
	mut h := signing_method_blake2b.new()

	assert "BLAKE2B" == h.alg()
	assert 32 == h.sign_length()

	mut claims := map[string]string{}
	claims["aud"] = "example.com"
	claims["iat"] = "foo"

	key := "12345678901234567890as1234567890"

	token_string := h.sign[map[string]string](claims, key.bytes())!
	assert token_string.len > 0

	parsed := h.parse(token_string, key.bytes())!

	claims2 := parsed.get_claims()!
	claims21 := claims2.as_map_of_strings()
	assert "example.com" == claims21["aud"]
	assert "foo" == claims21["iat"]
}

fn test_signing_method_blake2b_check() {
	key := "0323354b2b0fa5bc837e0665777ba68f5ab328e6f054c928a90f84b2d2502ebfd3fb5a92d20647ef968ab4c377623d223d2e2172052e4f08c0cd9af567d080a3"
	token_str := "eyJ0eXAiOiJKV1QiLCJhbGciOiJCTEFLRTJCIn0.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.zVtM3_PWCeOBjiV3bJcx1KoxeZCUs7zqfy6DF2mfb9M"

	key_bytes := hex.decode(key)!

	mut h := signing_method_blake2b.new()

	mut claims := map[string]JsonAny{}
	claims["iss"] = JsonAny("joe")
	claims["exp"] = JsonAny(1300819380)
	claims["http://example.com/is_root"] = JsonAny(true)

	token_string := h.sign[map[string]JsonAny](claims, key_bytes)!
	assert token_string.len > 0

	parsed := h.parse(token_str, key_bytes)!

	claims2 := parsed.get_claims()!
	claims21 := claims2.as_map_of_strings()
	assert "joe" == claims21["iss"]
}

fn test_signing_method_blake2b_check_fail() {
	key := "0323354b2b0fa5bc837e0665777ba68f5ab328e6f054c928a90f84b2d2502ebfd3fb5a92d20647ef968ab4c377623d223d2e2172052e4f08c0cd9af567d080a3"
	token_str := "eyJ0eXAiOiJKV1QiLCJhbGciOiJCTEFLRTJCIn0.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.zVtM3_PWCeOBjiV3bJcx1KoxeZCUs7zqfy6DF2mfb12"

	key_bytes := hex.decode(key)!

	mut h := signing_method_blake2b.new()

	mut need_err := false
	h.parse(token_str, key_bytes) or {
		need_err = true
		assert err.msg() == "JWT token verify fail"
	}

	assert need_err
}

fn test_signing_method_hs256_data() {
	mut h := signing_method_hs256.new()

	mut claims := map[string]string{}
	claims["aud"] = "example.com"
	claims["iat"] = "foo"

	key := "test-key"

	token_string := h.sign[map[string]string](claims, key.bytes())!
	assert token_string.len > 0

	parsed := h.parse(token_string, key.bytes())!

	headers := parsed.get_header()!
	assert "JWT" == headers.get_type()?
	assert "HS256" == headers.get_algorithm()?

	claims2 := parsed.get_claim()!
	assert "example.com" == claims2.get_audience()?
	assert "foo" == claims2.get_string("iat")?
}

fn test_signing_method_hs256_data2() {
	mut h := signing_method_hs256.new()

	mut header := map[string]string{}
	header["typ"] = "JWT"
	header["alg"] = "HS256"
	header["kid"] = "your key"
	header["cty"] = "utf8"
	header["ui"] = "JWK"

	mut claims := map[string]JsonAny{}
	claims["exp"] = JsonAny(1788969629)
	claims["nbf"] = JsonAny(1786377689)
	claims["iat"] = JsonAny(1786377629)
	claims["aud"] = JsonAny("example.com")
	claims["iss"] = JsonAny("issuer")
	claims["sub"] = JsonAny("subject")
	claims["jti"] = JsonAny("JwtId")
	claims["userid"] = JsonAny("test")

	key := "test-key"

	token_string := h.sign_with_header[map[string]string, map[string]JsonAny](header, claims, key.bytes())!
	assert token_string.len > 0

	parsed := h.parse(token_string, key.bytes())!

	headers := parsed.get_header()!
	assert "JWT" == headers.get_type()?
	assert "HS256" == headers.get_algorithm()?
	assert "your key" == headers.get_key_id()?
	assert "utf8" == headers.get_content_type()?
	assert "JWK" == headers.get_string("ui")?

	a1 := headers.get_any("ui")?
	assert "JWK" == a1.str()

	assert "" == headers.get_string("ui2") or { "" }

	claims2 := parsed.get_claim()!
	assert 1788969629 == claims2.get_expiration_time()?
	assert 1786377689 == claims2.get_not_before()?
	assert 1786377629 == claims2.get_issued_at()?
	assert "example.com" == claims2.get_audience()?
	assert "issuer" == claims2.get_issuer()?
	assert "subject" == claims2.get_subject()?
	assert "JwtId" == claims2.get_id()?
	assert "test" == claims2.get_string("userid")?

	a2 := claims2.get_any("userid")?
	assert "test" == a2.str()

	assert "" == claims2.get_string("userid2") or { "" }
}

fn test_signing_method_hs256_data3() {
	mut h := signing_method_hs256.new()

	mut header := RegisteredHeaders{
		type: "JWT"
		algorithm: "HS256"
	}

	mut claims := RegisteredClaims{
		issuer: "issuer"
		subject: "subject"
		expires_at: 1788969629
	}

	key := "test-key"

	token_string := h.sign_with_header[RegisteredHeaders, RegisteredClaims](header, claims, key.bytes())!
	assert token_string.len > 0

	parsed := h.parse(token_string, key.bytes())!

	headers := parsed.get_headers_raw()
	assert '{"typ":"JWT","alg":"HS256"}' == headers

	claims2 := parsed.get_claims_raw()
	assert '{"iss":"issuer","sub":"subject","exp":1788969629}' == claims2
}

fn test_signing_method_hs256_data5() {
	mut h := signing_method_hs256.new()

	mut header := RegisteredHeaders{
		type: "JWT"
		algorithm: "HS256"
	}

	mut claims := RegisteredClaims{
		issuer: "issuer"
		subject: "subject"
		expires_at: 1788969629
	}

	key := "test-key"

	token_string := h.sign_with_header(header, claims, key.bytes())!
	assert token_string.len > 0

	parsed := h.parse(token_string, key.bytes())!

	headers := parsed.get_headers_raw()
	assert '{"typ":"JWT","alg":"HS256"}' == headers

	claims2 := parsed.get_claims_raw()
	assert '{"iss":"issuer","sub":"subject","exp":1788969629}' == claims2
}

fn test_signing_method_hs256_data6() {
	mut h := signing_method_hs256.new()

	mut claims := map[string]string{}
	claims["aud"] = "example.com"
	claims["iat"] = "foo"

	key := "test-key"

	token_string := h.sign(claims, key.bytes())!
	assert token_string.len > 0

	parsed := h.parse(token_string, key.bytes())!

	headers := parsed.get_header()!
	assert "JWT" == headers.get_type()?
	assert "HS256" == headers.get_algorithm()?

	claims2 := parsed.get_claim()!
	assert "example.com" == claims2.get_audience()?
	assert "foo" == claims2.get_string("iat")?
}

fn test_registered_std() {
	assert 'typ' == registered_std_headers.type
	assert 'alg' == registered_std_headers.algorithm
	assert 'kid' == registered_std_headers.key_id
	assert 'cty' == registered_std_headers.content_type
	assert 'enc' == registered_std_headers.encryption

	assert 'aud' == registered_std_claims.audience
	assert 'exp' == registered_std_claims.expiration_time
	assert 'jti' == registered_std_claims.id
	assert 'iat' == registered_std_claims.issued_at
	assert 'iss' == registered_std_claims.issuer
	assert 'nbf' == registered_std_claims.not_before
	assert 'sub' == registered_std_claims.subject
}
