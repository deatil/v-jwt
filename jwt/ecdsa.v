module jwt

import hash
import crypto.ecdsa
import crypto.sha256
import crypto.sha512

pub const signing_es256 = ECDSA{
	name: "ES256"
	hash: sha256.new()
	key_size: 32
}
pub const signing_es384 = ECDSA{
	name: "ES384"
	hash: sha512.new384()
	key_size: 48
}
pub const signing_es512 = ECDSA{
	name: "ES512"
	hash: sha512.new()
	key_size: 66
}
pub const signing_es256k = ECDSA{
	name: "ES256K"
	hash: sha256.new()
	key_size: 32
}

pub struct ECDSA {
	name     string
	hash     &hash.Hash = unsafe { nil }
	key_size int
}

pub fn (e ECDSA) alg() string {
	return e.name
}

pub fn (e ECDSA) sign_length() int {
	return 2 * e.key_size
}

pub fn (e ECDSA) sign(msg []u8, key ecdsa.PrivateKey) ![]u8 {
	siged := key.sign(msg, ecdsa.SignerOpts{
		hash_config: .with_custom_hash
		allow_custom_hash: true
		allow_smaller_size: true
		custom_hash: e.hash
	})!

	return siged
}

pub fn (e ECDSA) verify(msg []u8, signature []u8, key ecdsa.PublicKey) !bool {
	res := key.verify(msg, signature, ecdsa.SignerOpts{
		hash_config: .with_custom_hash
		allow_custom_hash: true
		allow_smaller_size: true
		custom_hash: e.hash
	})!
	return res
}

