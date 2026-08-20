module jwt

import crypto.pem
import crypto.ed25519
import x.encoding.asn1

pub fn parse_eddsa_privatekey_pem(str string) !ed25519.PrivateKey {
	block, _ := pem.decode(str) or {pem.Block{}, ""}
	key := parse_eddsa_privatekey_der(block.data)!
	return key
}

pub fn parse_eddsa_publickey_pem(str string) !ed25519.PublicKey {
	block, _ := pem.decode(str) or {pem.Block{}, ""}
	key := parse_eddsa_publickey_der(block.data)!
	return key
}

pub fn parse_eddsa_privatekey_der(bytes []u8) !ed25519.PrivateKey {
	elem := asn1.decode(bytes)!
	assert elem.tag().equal(asn1.default_sequence_tag)

	seq := elem.into_object[asn1.Sequence]()!
	fields := seq.fields()

	ver := fields[0].into_object[asn1.Integer]()!
	version := ver.as_i64()!
    if version != 0 {
        return error("JWT EdDSA PKCS8 Version Error")
    }

	oid_seq := fields[1].into_object[asn1.Sequence]()!
	oid_seq_fields := oid_seq.fields()

	oid := oid_seq_fields[0].into_object[asn1.ObjectIdentifier]()!
	check_eddsa_publickey_oid(oid)!

	prikey_octet := fields[2].into_object[asn1.OctetString]()!
	prikey_octet_bytes := prikey_octet.payload()!

	elem2 := asn1.decode(prikey_octet_bytes)!

	prikey_octet2 := elem2.into_object[asn1.OctetString]()!
	parse_prikey_bytes := prikey_octet2.payload()!

    if parse_prikey_bytes.len != ed25519.seed_size {
        return error("JWT EdDSA Private Key Bytes Length Error")
    }

	prikey := ed25519.new_key_from_seed(parse_prikey_bytes)
	return prikey
}

pub fn parse_eddsa_publickey_der(bytes []u8) !ed25519.PublicKey {
	elem := asn1.decode(bytes)!
	assert elem.tag().equal(asn1.default_sequence_tag)

	seq := elem.into_object[asn1.Sequence]()!
	fields := seq.fields()

	oid_seq := fields[0].into_object[asn1.Sequence]()!
	oid_fields := oid_seq.fields()

	oid := oid_fields[0].into_object[asn1.ObjectIdentifier]()!
	check_eddsa_publickey_oid(oid)!

	pubkey_bitstring := fields[1].into_object[asn1.BitString]()!
	pubkey_bytes := pubkey_bitstring.data()

    if pubkey_bytes.len != ed25519.public_key_size {
        return error("JWT EdDSA Public Key Bytes Length Error")
    }

	pubkey := ed25519.PublicKey(pubkey_bytes)
	return pubkey
}

fn check_eddsa_publickey_oid(oid asn1.ObjectIdentifier) ! {
	oid_eddsa_publickey := asn1.ObjectIdentifier.new("1.3.101.112")!
	if !oid_eddsa_publickey.equal(oid) {
		return error("JWT EdDSA Oid Error")
	}
}
