module jwt

fn test_token() {
	mut header := map[string]string{}
	header["typ"] = "JWT"
	header["alg"] = "ES256"

	mut claims := map[string]string{}
	claims["aud"] = "example.com"
	claims["iat"] = "foo"

	signature := "test-signature"

	check1 := "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJleGFtcGxlLmNvbSIsImlhdCI6ImZvbyJ9"
    check2 := "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJleGFtcGxlLmNvbSIsImlhdCI6ImZvbyJ9.dGVzdC1zaWduYXR1cmU"

    mut token := Token.new()
    token.set_header[map[string]string](header)
    token.set_claims[map[string]string](claims)
    token.with_signature(signature)

	res1 := token.signing_string()
	assert res1 == check1

	res2 := token.signed_string()
	assert res2 == check2

	// ===================

	mut token2 := Token.new()
	token2.parse(check1)

	header2 := token2.get_headers()!
	header21 := header2.as_map_of_strings()
	assert "JWT" == header21["typ"]
	assert "ES256" == header21["alg"]

	claims2 := token2.get_claims()!
	claims21 := claims2.as_map_of_strings()
	assert "example.com" == claims21["aud"]
	assert "foo" == claims21["iat"]

	signature2 := token2.get_signature()
	assert 0 == signature2.len

	part_count := token2.get_part_count()
	assert 2 == part_count

	// ===================
	
	mut token3 := Token.new()
	token3.parse(check2)

	header3 := token3.get_headers()!
	header31 := header3.as_map_of_strings()
	assert "JWT" == header31["typ"]
	assert "ES256" == header31["alg"]

	claims3 := token3.get_claims()!
	claims31 := claims3.as_map_of_strings()
	assert "example.com" == claims31["aud"]
	assert "foo" == claims31["iat"]

	signature3 := token3.get_signature()
	assert signature == signature3

	part_count3 := token3.get_part_count()
	assert 3 == part_count3

	// ===================

	check3 := "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9"
	
	mut token6 := Token.new()
	token6.parse(check3)

	sig61 := token6.get_raw()
	assert check3 == sig61

	sig6 := token6.get_msg()
	assert check3 == sig6

	part_count6 := token6.get_part_count()
	assert 1 == part_count6
}


