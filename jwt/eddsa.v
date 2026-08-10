module jwt

import crypto.ed25519

pub const signing_eddsa = EdDSA.new("EdDSA")
pub const signing_ed25519 = EdDSA.new("ED25519")

pub struct EdDSA {
	name string
}

pub fn EdDSA.new(name string) EdDSA {
	return EdDSA{
		name, 
	}
}

pub fn (e EdDSA) alg() string {
	return e.name
}

pub fn (e EdDSA) sign_length() int {
	return ed25519.signature_size
}

pub fn (e EdDSA) sign(msg []u8, key ed25519.PrivateKey) ![]u8 {
	res := ed25519.sign(key, msg)!
	return res
}

pub fn (e EdDSA) verify(msg []u8, signature []u8, key ed25519.PublicKey) !bool {
	if signature.len != ed25519.signature_size {
		return false
	}

	res := ed25519.verify(key, msg, signature)!
	return res
}
