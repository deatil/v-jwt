module jwt

import time

fn test_signing_method_hs256_builder() {
	now := time.now()
	exp := now.add_days(30).unix()
	nbf := now.add_seconds(60).unix()

	mut b := signing_method_hs256.build()

	b.set_header("ui", JsonAny("JWK"))
	b.permitted_for("audience")
	b.expires_at(int(exp))
	b.identified_by("JwtId")
	b.issued_at(int(now.unix()))
	b.issued_by("issuer")
	b.can_only_be_used_after(int(nbf))
	b.related_to("subject")
	b.set_claim("userid", JsonAny("test"))

    key := "test-key"

	token := b.get_token(key.bytes())!

	token_string := token.signed_string()
	assert token_string.len > 0

	mut p := signing_method_hs256
	parsed := p.parse(token_string, key.bytes())!

	headers := parsed.get_headers_raw()
	assert headers == '{"ui":"JWK","typ":"JWT","alg":"HS256"}'

	claims2 := parsed.get_claims()!
	claims21 := claims2.as_map_of_strings()
	assert "JwtId" == claims21["jti"]
	assert "subject" == claims21["sub"]
}

fn test_signing_method_hs256_builder2() {
	now := 1786377629
	exp := 1788969629
	nbf := 1786377689

	mut b := signing_method_hs256.build()

	b.set_header("ui", JsonAny("JWK"))
	b.permitted_for("audience")
	b.expires_at(int(exp))
	b.identified_by("JwtId")
	b.issued_at(int(now))
	b.issued_by("issuer")
	b.can_only_be_used_after(int(nbf))
	b.related_to("subject")
	b.set_claim("userid", JsonAny("test"))

    key := "test-key"

	token := b.get_token(key.bytes())!

	token_string := token.signed_string()
	assert token_string.len > 0

	mut p := signing_method_hs256
	parsed := p.parse(token_string, key.bytes())!

	headers := parsed.get_headers_raw()
	assert headers == '{"ui":"JWK","typ":"JWT","alg":"HS256"}'

	claims := parsed.get_claims_raw()
	assert claims == '{"aud":"audience","exp":1788969629,"jti":"JwtId","iat":1786377629,"iss":"issuer","nbf":1786377689,"sub":"subject","userid":"test"}'
}