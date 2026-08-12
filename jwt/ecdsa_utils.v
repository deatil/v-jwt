module jwt

import crypto.ecdsa
import x.encoding.asn1

pub fn parse_ecdsa_privatekey_pem(str string) !ecdsa.PrivateKey {
	return ecdsa.privkey_from_string(str)
}

pub fn parse_ecdsa_publickey_pem(str string) !ecdsa.PublicKey {
	return ecdsa.pubkey_from_string(str)
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
