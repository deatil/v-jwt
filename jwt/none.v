module jwt

pub const signing_none = None{
	name: "none"
}

pub struct None {
pub:
	name string
}

pub fn (n None) alg() string {
	return n.name
}

pub fn (n None) sign_length() int {
	return 0
}

pub fn (n None) sign(msg []u8, key []u8) ![]u8 {
	return []
}

pub fn (n None) verify(msg []u8, signature []u8, key []u8) !bool {
	if signature.len > 0 {
		return false
	}
	
	return true
}
