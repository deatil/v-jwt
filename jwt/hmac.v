module jwt

import hash
import crypto.hmac
import crypto.md5
import crypto.sha1
import crypto.sha256
import crypto.sha512

type Hash = hash.Hash

pub const signing_hmd5 = Hmac.new("HMD5", md5.new())
pub const signing_hsha1 = Hmac.new("HSHA1", sha1.new())
pub const signing_hs224 = Hmac.new("HS224", sha256.new224())
pub const signing_hs256 = Hmac.new("HS256", sha256.new())
pub const signing_hs384 = Hmac.new("HS384", sha512.new384())
pub const signing_hs512 = Hmac.new("HS512", sha512.new())

pub struct Hmac {
	name string
mut:
	hash Hash
}

pub fn Hmac.new(name string, h Hash) Hmac {
	return Hmac{
		name, 
		h,
	}
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
		d.write(msg) or { panic(err) }
		return d.sum([])
	}, h2.block_size())
	return hres
}

pub fn (h Hmac) verify(msg []u8, signature []u8, key []u8) !bool {
	mut h2 := h.hash
	hres := hmac.new(key, msg, fn [h] (msg []u8) []u8 {
		mut d := h.hash
		d.reset()
		d.write(msg) or { panic(err) }
		return d.sum([])
	}, h2.block_size())
	return hmac.equal(hres, signature)
}
