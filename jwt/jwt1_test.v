module jwt

import encoding.hex

fn test_signing_method_hs256() {
	mut h := signing_method_hs256

	assert "HS256" == h.alg()
	assert 32 == h.sign_length()

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

fn test_signing_method_hs384() {
	mut h := signing_method_hs384

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
	mut h := signing_method_hs512

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
	mut h := signing_method_hs224

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
	mut h := signing_method_hsha1

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
	mut h := signing_method_hmd5

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
	mut h := signing_method_none

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

	mut h := signing_method_hs256

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

	mut h := signing_method_hs384

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

	mut h := signing_method_hs512

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
	mut h := signing_method_blake2b

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

	mut h := signing_method_blake2b

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

	mut h := signing_method_blake2b

	mut need_err := false
	h.parse(token_str, key_bytes) or {
		need_err = true
		assert err.msg() == "JWT token verify fail"
	}

	assert need_err
}



