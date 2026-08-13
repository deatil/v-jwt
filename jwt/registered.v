module jwt

pub struct RegisteredHeaders {
pub:
	// type
	type string @[json: 'typ'; omitempty]
	// algorithm
	algorithm string @[json: 'alg'; omitempty]
	// key id
	key_id string @[json: 'kid'; omitempty]
	// content type
	content_type string @[json: 'cty'; omitempty]
}

pub struct RegisteredClaims {
pub:
	// the `iss` (Issuer) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1
	issuer string @[json: 'iss'; omitempty]

	// the `sub` (Subject) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2
	subject string @[json: 'sub'; omitempty]

	// the `aud` (Audience) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
	audience string @[json: 'aud'; omitempty]

	// the `exp` (Expiration Time) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
	expires_at i64 @[json: 'exp'; omitempty]

	// the `nbf` (Not Before) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
	not_before i64 @[json: 'nbf'; omitempty]

	// the `iat` (Issued At) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6
	issued_at i64 @[json: 'iat'; omitempty]

	// the `jti` (JWT ID) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7
	id string @[json: 'jti'; omitempty]
}
