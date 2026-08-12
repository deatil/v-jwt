module jwt

pub struct Builder[S, V] {
mut:
	headers map[string]JsonAny
	claims  map[string]JsonAny
	signer  ISigner[S, V]
}

pub fn Builder.new[S, V](signer ISigner[S, V]) Builder[S, V] {
	return Builder{
		headers: map[string]JsonAny{}
		claims:  map[string]JsonAny{}
		signer:  signer
	}
}

// Configures a header item
pub fn (mut b Builder[S, V]) set_header(name string, value JsonAny) {
	b.headers[name] = value
}

// Configures a claim item
pub fn (mut b Builder[S, V]) set_claim(name string, value JsonAny) {
	b.claims[name] = value
}

pub fn (mut b Builder[S, V]) header_type(value string) {
	b.set_header("typ", JsonAny(value))
}

pub fn (mut b Builder[S, V]) header_algo(value string) {
	b.set_header("alg", JsonAny(value))
}

pub fn (mut b Builder[S, V]) permitted_for(value string) {
	b.set_claim("aud", JsonAny(value))
}

pub fn (mut b Builder[S, V]) expires_at(value i64) {
	b.set_claim("exp", JsonAny(value))
}

pub fn (mut b Builder[S, V]) identified_by(value string) {
	b.set_claim("jti", JsonAny(value))
}

pub fn (mut b Builder[S, V]) issued_at(value i64) {
	b.set_claim("iat", JsonAny(value))
}

pub fn (mut b Builder[S, V]) issued_by(value string) {
	b.set_claim("iss", JsonAny(value))
}

pub fn (mut b Builder[S, V]) can_only_be_used_after(value i64) {
	b.set_claim("nbf", JsonAny(value))
}

pub fn (mut b Builder[S, V]) related_to(value string) {
	b.set_claim("sub", JsonAny(value))
}

pub fn (b Builder[S, V]) get_token(key S) !Token {
	mut headers := b.headers.clone()

	if 'typ' !in headers {
		headers["typ"] = JsonAny("JWT")
	}
	if 'alg' !in headers {
		headers["alg"] = JsonAny(b.signer.alg())
	}

    mut t := Token.new()
    t.set_header[map[string]JsonAny](headers)
    t.set_claims[map[string]JsonAny](b.claims)

	signing_string := t.signing_string()
	signature := b.signer.sign(signing_string.bytes(), key)!

    t.with_signature(signature.bytestr())

	return t
}

