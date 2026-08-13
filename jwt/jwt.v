module jwt

import crypto.ecdsa
import crypto.ed25519

pub const signing_method_hmd5 = Jwt.new[[]u8, []u8](signing_hmd5)
pub const signing_method_hsha1 = Jwt.new[[]u8, []u8](signing_hsha1)
pub const signing_method_hs224 = Jwt.new[[]u8, []u8](signing_hs224)
pub const signing_method_hs256 = Jwt.new[[]u8, []u8](signing_hs256)
pub const signing_method_hs384 = Jwt.new[[]u8, []u8](signing_hs384)
pub const signing_method_hs512 = Jwt.new[[]u8, []u8](signing_hs512)

pub const signing_method_blake2b = Jwt.new[[]u8, []u8](signing_blake2b)

pub const signing_method_eddsa = Jwt.new[ed25519.PrivateKey, ed25519.PublicKey](signing_eddsa)
pub const signing_method_ed25519 = Jwt.new[ed25519.PrivateKey, ed25519.PublicKey](signing_ed25519)

pub const signing_method_es256 = Jwt.new[ecdsa.PrivateKey, ecdsa.PublicKey](signing_es256)
pub const signing_method_es384 = Jwt.new[ecdsa.PrivateKey, ecdsa.PublicKey](signing_es384)
pub const signing_method_es512 = Jwt.new[ecdsa.PrivateKey, ecdsa.PublicKey](signing_es512)
pub const signing_method_es256k = Jwt.new[ecdsa.PrivateKey, ecdsa.PublicKey](signing_es256k)

pub const signing_method_none = Jwt.new[[]u8, []u8](signing_none)

pub interface ISigner[S, V] {
	alg() string
	sign_length() int
	sign(msg []u8, key S) ![]u8
	verify(msg []u8, signature []u8, key V) !bool
}

pub struct Jwt[S, V] {
	signer ISigner[S, V]
}

pub fn Jwt.new[S, V](signer ISigner[S, V]) Jwt[S, V] {
	return Jwt[S, V]{
		signer, 
	}
}

pub fn (j Jwt[S, V]) new() Jwter[S, V] {
	return Jwter[S, V]{
		signer: j.signer
	}
}

pub struct Jwter[S, V] {
	signer ISigner[S, V]
}

pub fn (j Jwter[S, V]) get_signer() ISigner[S, V] {
	return j.signer
}

pub fn (j Jwter[S, V]) alg() string {
	return j.signer.alg()
}

pub fn (j Jwter[S, V]) sign_length() int {
	return j.signer.sign_length()
}

pub fn (j Jwter[S, V]) sign[T](claims T, sign_key S) !string {
	mut header := map[string]string{}
	header["typ"] = "JWT"
	header["alg"] = j.signer.alg()

	return j.sign_with_header[map[string]string, T](header, claims, sign_key);
}

pub fn (j Jwter[S, V]) sign_with_header[A, B](header A, claims B, sign_key S) !string {
    mut t := Token.new()
    t.set_header[A](header)
    t.set_claims[B](claims)

	signing_string := t.signing_string()
	signature := j.signer.sign(signing_string.bytes(), sign_key)!

    t.with_signature(signature.bytestr())

	return t.signed_string()
}

pub fn (j Jwter[S, V]) parse(token_string string, verify_key V) !Token {
	mut t := Token.new()
	t.parse(token_string)

	if t.get_part_count() < 2 {
		return error("JWT token invalid")
	}

	header := t.get_headers()!
	header_map := header.as_map_of_strings()

	typ := header_map["typ"] or {""}
	if typ.len > 0 && typ != "JWT" {
		return error("JWT token type invalid")
	}

	alg := header_map["alg"] or {""}
	if alg != j.signer.alg() {
		return error("JWT token alg invalid")
	}

	signature := t.get_signature()
	signing_string := t.get_msg()

	verifyed := j.signer.verify(signing_string.bytes(), signature.bytes(), verify_key)!
	if !verifyed {
		return error("JWT token verify fail")
	}

	return t
}

pub fn (j Jwter[S, V]) build() Builder[S] {
	return Builder.new[S, V](j.signer)
}
