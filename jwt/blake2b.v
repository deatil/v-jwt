module jwt

import crypto.hmac
import crypto.blake2b

pub const signing_blake2b = Blake2b{
	name: "BLAKE2B"
}

pub struct Blake2b {
pub:
	name string
}

pub fn (b Blake2b) alg() string {
	return b.name
}

pub fn (b Blake2b) sign_length() int {
	return blake2b.size256
}

pub fn (b Blake2b) sign(msg []u8, key []u8) ![]u8 {
	if key.len * 8 < 256 {
		return error("JWT Blake2b Key Too Short")
	}

	mut d := blake2b.new_pmac256(key)!
	d.write(msg)!
	return d.checksum()
}

pub fn (b Blake2b) verify(msg []u8, signature []u8, key []u8) !bool {
	if key.len * 8 < 256 {
		return error("JWT Blake2b Key Too Short")
	}

	mut d := blake2b.new_pmac256(key)!
	d.write(msg)!
	hres := d.checksum()

	return hmac.equal(hres, signature)
}
