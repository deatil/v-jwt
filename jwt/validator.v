module jwt

pub struct Validator {
mut:
	claims map[string]JsonAny
	leeway i64
}

pub fn Validator.new(token Token) Validator {
	claims := token.get_claimss_t[map[string]JsonAny]() or { map[string]JsonAny{} }

	return Validator{
		claims: claims
		leeway: 0 
	}
}

pub fn (mut v Validator) with_leeway(leeway i64) {
	v.leeway = leeway
}

pub fn (v Validator) is_permitted_for(audiences []string) bool {
	audience := v.claims["aud"] or {JsonAny("")}

	for aud in audiences {
		if aud == audience.str() {
			return true
		}
	}

	return false
}

pub fn (v Validator) is_identified_by(id string) bool {
	val := v.claims["jti"] or {JsonAny("")}

	if val.str() == id {
		return true
	}

	return false
}

pub fn (v Validator) is_related_to(subjects []string) bool {
	val := v.claims["sub"] or {JsonAny("")}

	for sub in subjects {
		if sub == val.str() {
			return true
		}
	}

	return false
}

pub fn (v Validator) has_been_issued_by(issuers []string) bool {
	val := v.claims["iss"] or {JsonAny("")}

	for iss in issuers {
		if iss == val.str() {
			return true
		}
	}

	return false
}

pub fn (v Validator) has_been_issued_before(now i64) bool {
	val := v.claims["iat"] or {JsonAny(0)}

	vv := val.i64()
	if vv > 0 {
		if now+v.leeway > vv {
			return true
		}

		return false
	}

	return false
}

pub fn (v Validator) is_minimum_time_before(now i64) bool {
	val := v.claims["nbf"] or {JsonAny(0)}

	vv := val.i64()
	if vv > 0 {
		if now+v.leeway > vv {
			return true
		}

		return false
	}

	return true
}

pub fn (v Validator) is_expired(now i64) bool {
	val := v.claims["exp"] or {JsonAny(0)}

	vv := val.i64()
	if vv > 0 {
		if now-v.leeway < vv {
			return false
		}

		return true
	}

	return false
}

