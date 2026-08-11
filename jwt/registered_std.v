module jwt

// Defines "JSON Web Token Headers" struct
pub struct RegisteredStdHeaders {
pub:
	type         string
	algorithm    string
	key_id       string
	content_type string
	encryption   string
}

// Defines "JSON Web Token Claims" struct
pub struct RegisteredStdClaims {
pub:
	audience        string
	expiration_time string
	id              string
	issued_at       string
	issuer          string
	not_before      string
	subject         string
}

// Defines the list of headers that are registered in the IANA "JSON Web Token Headers" registry
pub const registered_std_headers = RegisteredStdHeaders{
	type:         "typ"
	algorithm:    "alg"
	key_id:       "kid"
	content_type: "cty"
	encryption:   "enc"
}

// Defines the list of claims that are registered in the IANA "JSON Web Token Claims" registry
pub const registered_std_claims = RegisteredStdClaims{
	audience:        "aud"
	expiration_time: "exp"
	id:              "jti"
	issued_at:       "iat"
	issuer:          "iss"
	not_before:      "nbf"
	subject:         "sub"
}
