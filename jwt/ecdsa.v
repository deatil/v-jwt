module jwt

import hash
import encoding.hex
import crypto.ecdsa
import crypto.sha256
import crypto.sha512
import x.encoding.asn1

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
	sig := key.sign(msg, ecdsa.SignerOpts{
		hash_config: .with_custom_hash
		allow_custom_hash: true
		allow_smaller_size: true
		custom_hash: e.hash
	})!

	res := SigData.decode(sig)!

	r_bytes := hex.decode(res.r.hex())!
	s_bytes := hex.decode(res.s.hex())!

	mut siged := []u8{len: 2 * e.key_size}

	copy(mut siged[e.key_size - r_bytes.len..e.key_size], r_bytes)
	copy(mut siged[2 * e.key_size - s_bytes.len..], s_bytes)

	return siged
}

pub fn (e ECDSA) verify(msg []u8, signature []u8, key ecdsa.PublicKey) !bool {
	if signature.len != 2 * e.key_size {
		return false
	}

	r := asn1.Integer.from_hex(signature[..e.key_size].hex())!
	s := asn1.Integer.from_hex(signature[e.key_size..].hex())!

	sig := SigData{r, s}
	siged := asn1.encode(sig)!

	res := key.verify(msg, siged, ecdsa.SignerOpts{
		hash_config: .with_custom_hash
		allow_custom_hash: true
		allow_smaller_size: true
		custom_hash: e.hash
	})!
	return res
}
