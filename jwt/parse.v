module jwt

pub interface IParseSigner[V] {
	alg() string
	sign_length() int
	parse(token_string string, verify_key V) !Token
}

pub fn parse[V](signer IParseSigner[V], token_string string, verify_key V) !Token {
	return signer.parse(token_string, verify_key)
}