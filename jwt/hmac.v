module jwt

import hash
import crypto.hmac
import crypto.md5
import crypto.sha1
import crypto.sha256
import crypto.sha512

pub const signing_hmd5 = Hmac{
	name: "HMD5"
	hash: md5.new()
}
pub const signing_hsha1 = Hmac{
	name: "HSHA1"
	hash: sha1.new()
}
pub const signing_hs224 = Hmac{
	name: "HS224"
	hash: sha256.new224()
}
pub const signing_hs256 = Hmac{
	name: "HS256"
	hash: sha256.new()
}
pub const signing_hs384 = Hmac{
	name: "HS384"
	hash: sha512.new384()
}
pub const signing_hs512 = Hmac{
	name: "HS512"
	hash: sha512.new()
}

pub struct Hmac {
pub:
	name string
	hash &hash.Hash = unsafe { nil }
}

pub fn (h Hmac) alg() string {
	return h.name
}

pub fn (h Hmac) sign_length() int {
	mut h2 := h.hash
	return h2.size()
}

pub fn (h Hmac) sign(msg []u8, key []u8) ![]u8 {
	mut h2 := h.hash
	hres := hmac.new(key, msg, fn [h] (msg []u8) []u8 {
		mut d := h.hash
		d.reset()
		d.write(msg) or { return [] }
		return d.sum([])
	}, h2.block_size())
	return hres
}

pub fn (h Hmac) verify(msg []u8, signature []u8, key []u8) !bool {
	mut h2 := h.hash
	hres := hmac.new(key, msg, fn [h] (msg []u8) []u8 {
		mut d := h.hash
		d.reset()
		d.write(msg) or { return [] }
		return d.sum([])
	}, h2.block_size())
	return hmac.equal(hres, signature)
}
