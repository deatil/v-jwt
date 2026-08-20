module jwt

import encoding.hex
import crypto.ecdsa
import x.encoding.asn1

pub fn parse_ecdsa_privatekey_pem(str string) !ecdsa.PrivateKey {
	return ecdsa.privkey_from_string(str)
}

pub fn parse_ecdsa_publickey_pem(str string) !ecdsa.PublicKey {
	return ecdsa.pubkey_from_string(str)
}

fn converter_from_asn1(sig []u8, key_size int) ![]u8 {
	res := SigData.decode(sig)!

	r_bytes := hex.decode(res.r.hex())!
	s_bytes := hex.decode(res.s.hex())!

	mut new_sig := []u8{len: 2 * key_size}

	copy(mut new_sig[key_size - r_bytes.len..key_size], r_bytes)
	copy(mut new_sig[2 * key_size - s_bytes.len..], s_bytes)

	return new_sig
}

fn converter_to_asn1(signature []u8, key_size int) ![]u8 {
	if signature.len != 2 * key_size {
		return error("JWT signature length ${signature.len} bytes not equal ${2 * key_size} bytes.")
	}

	r := asn1.Integer.from_hex(signature[..key_size].hex())!
	s := asn1.Integer.from_hex(signature[key_size..].hex())!

	sig := SigData{r, s}
	new_sig := asn1.encode(sig)!

	return new_sig
}

struct SigData {
	r asn1.Integer
	s asn1.Integer
}

fn (sd SigData) tag() asn1.Tag {
	return asn1.default_sequence_tag
}

fn (sd SigData) payload() ![]u8 {
	kd := asn1.new_key_default()
	payload := asn1.make_payload[SigData](sd, kd)!
	return payload
}

fn SigData.decode(bytes []u8) !SigData {
	elem := asn1.decode(bytes)!
	assert elem.tag().equal(asn1.default_sequence_tag)

	seq := elem.into_object[asn1.Sequence]()!
	fields := seq.fields()

	r := fields[0].into_object[asn1.Integer]()!
	s := fields[1].into_object[asn1.Integer]()!

	return SigData{r, s}
}
