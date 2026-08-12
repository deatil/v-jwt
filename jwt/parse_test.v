module jwt

import encoding.hex

fn test_parse_func() {
    key := "0323354b2b0fa5bc837e0665777ba68f5ab328e6f054c928a90f84b2d2502ebfd3fb5a92d20647ef968ab4c377623d223d2e2172052e4f08c0cd9af567d080a3"
    token_str := "eyJ0eXAiOiJKV1QiLCJhbGciOiJCTEFLRTJCIn0.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.zVtM3_PWCeOBjiV3bJcx1KoxeZCUs7zqfy6DF2mfb9M"

	key_bytes := hex.decode(key)!

	parsed := parse[[]u8](signing_method_blake2b, token_str, key_bytes)!

	claims2 := parsed.get_claims()!
	claims21 := claims2.as_map_of_strings()
	assert "joe" == claims21["iss"]
}