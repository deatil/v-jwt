module jwt

pub struct Token {
mut:
	raw       string
	msg       string
	header    string
	claims    string
	signature string
}

pub fn Token.new() Token {
	return Token{}
}

pub fn Token.from_string(token_string string) Token {
	mut t := Token{}
	t.parse(token_string)
	return t
}

pub fn (mut t Token) with_header(header string) {
	t.header = header
}

pub fn (mut t Token) set_header[T](header T) {
	t.header = json_encode[T](header)
}

pub fn (mut t Token) with_claims(claims string) {
	t.claims = claims
}

pub fn (mut t Token) set_claims[T](claims T) {
	t.claims = json_encode[T](claims)
}

pub fn (mut t Token) with_signature(signature string) {
	t.signature = signature
}

pub fn (t Token) signing_string() string {
	return t.signing(false)
}

pub fn (t Token) signed_string() string {
	return t.signing(true)
}

fn (t Token) signing(need_sign bool) string {
	header := base64_url_encode(t.header)
	claims := base64_url_encode(t.claims)

	mut buf := "${header}.${claims}"
	if need_sign {
		signature := base64_url_encode(t.signature)
		buf = "${buf}.${signature}"
	}

	return buf
}

pub fn (mut t Token) parse(token_string string) {
	if token_string.len == 0 {
		return
	}

	t.raw = token_string

	split_tokens := token_string.split(".")
	if split_tokens.len > 0 {
		t.header = base64_url_decode(split_tokens[0])
	} else {
		t.header = ""
	}
	if split_tokens.len > 1 {
		t.claims = base64_url_decode(split_tokens[1])
	} else {
		t.claims = ""
	}
	if split_tokens.len > 2 {
		t.signature = base64_url_decode(split_tokens[2])
	} else {
		t.signature = ""
	}

	t.msg = t.get_raw_no_signature()
}

pub fn (t Token) get_raw() string {
	return t.raw
}

pub fn (t Token) get_msg() string {
	return t.msg
}

pub fn (t Token) get_part_count() int {
	split_tokens := t.raw.split(".")
	return split_tokens.len
}

fn (t Token) get_raw_no_signature() string {
	split_tokens := t.raw.split(".")
	if split_tokens.len <= 1 {
		return t.raw
	}

	mut header := ""
	mut claims := ""
	if split_tokens.len > 0 {
		header = split_tokens[0]
	}
	if split_tokens.len > 1 {
		claims = split_tokens[1]
	}

	return "${header}.${claims}"
}

pub fn (t Token) get_header() !HeadersData {
	return HeadersData.new(t)!
}

pub fn (t Token) get_headers() !JsonAny {
	return json_decode[JsonAny](t.header)
}

pub fn (t Token) get_headers_t[T]() !T {
	return json_decode[T](t.header)
}

pub fn (t Token) get_headers_raw() string {
	return t.header
}

pub fn (t Token) get_claim() !ClaimsData {
	return ClaimsData.new(t)!
}

pub fn (t Token) get_claims() !JsonAny {
	return json_decode[JsonAny](t.claims)
}

pub fn (t Token) get_claims_t[T]() !T {
	return json_decode[T](t.claims)
}

pub fn (t Token) get_claims_raw() string {
	return t.claims
}

pub fn (t Token) get_signature() string {
	return t.signature
}

pub struct HeadersData {
	headers map[string]JsonAny
}

pub fn HeadersData.new(token Token) !HeadersData {
	headers := token.get_headers_t[map[string]JsonAny]()!

	return HeadersData{
		headers: headers 
	}
}

pub fn (h HeadersData) get_type() ?string {
	return h.get_string("typ")
}

pub fn (h HeadersData) get_algorithm() ?string {
	return h.get_string("alg")
}

pub fn (h HeadersData) get_key_id() ?string {
	return h.get_string("kid")
}

pub fn (h HeadersData) get_content_type() ?string {
	return h.get_string("cty")
}

pub fn (h HeadersData) get_string(name string) ?string {
	res := h.headers[name] or { return none }
	return res.str()
}

pub fn (h HeadersData) get_any(name string) ?JsonAny {
	res := h.headers[name] or { return none }
	return res
}

pub struct ClaimsData {
	claims map[string]JsonAny
}

pub fn ClaimsData.new(token Token) !ClaimsData {
	claims := token.get_claims_t[map[string]JsonAny]()!

	return ClaimsData{
		claims: claims 
	}
}

pub fn (c ClaimsData) get_expiration_time() ?i64 {
	return c.get_int("exp")
}

pub fn (c ClaimsData) get_not_before() ?i64 {
	return c.get_int("nbf")
}

pub fn (c ClaimsData) get_issued_at() ?i64 {
	return c.get_int("iat")
}

pub fn (c ClaimsData) get_audience() ?string {
	return c.get_string("aud")
}

pub fn (c ClaimsData) get_issuer() ?string {
	return c.get_string("iss")
}

pub fn (c ClaimsData) get_subject() ?string {
	return c.get_string("sub")
}

pub fn (c ClaimsData) get_id() ?string {
	return c.get_string("jti")
}

pub fn (c ClaimsData) get_string(name string) ?string {
	res := c.claims[name] or { return none }
	return res.str()
}

pub fn (c ClaimsData) get_int(name string) ?i64 {
	res := c.claims[name] or { return none }
	return res.i64()
}

pub fn (c ClaimsData) get_any(name string) ?JsonAny {
	res := c.claims[name] or { return none }
	return res
}
