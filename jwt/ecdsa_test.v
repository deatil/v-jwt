module jwt

import crypto.ecdsa

fn test_es256() {
	mut h := signing_es256

	assert "ES256" == h.alg()
	assert 64 == h.sign_length()

	pubkey, prikey := ecdsa.generate_key(nid: .prime256v1)!

    msg := "test-data"

	signed := h.sign(msg.bytes(), prikey)!
	assert signed.len > 0

	veri := h.verify(msg.bytes(), signed, pubkey)!
	assert true == veri

	signed2 := "hello"
	veri2 := h.verify(msg.bytes(), signed2.bytes(), pubkey)!
	assert false == veri2
}

fn test_es384() {
	mut h := signing_es384

	assert "ES384" == h.alg()
	assert 96 == h.sign_length()

	pubkey, prikey := ecdsa.generate_key(nid: .secp384r1)!

    msg := "test-data"

	signed := h.sign(msg.bytes(), prikey)!
	assert signed.len > 0

	veri := h.verify(msg.bytes(), signed, pubkey)!
	assert true == veri

	signed2 := "hello"
	veri2 := h.verify(msg.bytes(), signed2.bytes(), pubkey)!
	assert false == veri2
}

fn test_es512() {
	mut h := signing_es512

	assert "ES512" == h.alg()
	assert 132 == h.sign_length()

	pubkey, prikey := ecdsa.generate_key(nid: .secp521r1)!

    msg := "test-data"

	signed := h.sign(msg.bytes(), prikey)!
	assert signed.len > 0

	veri := h.verify(msg.bytes(), signed, pubkey)!
	assert true == veri

	signed2 := "hello"
	veri2 := h.verify(msg.bytes(), signed2.bytes(), pubkey)!
	assert false == veri2
}

fn test_es256k() {
	mut h := signing_es256k

	assert "ES256K" == h.alg()
	assert 64 == h.sign_length()

	pubkey, prikey := ecdsa.generate_key(nid: .secp256k1)!

    msg := "test-data"

	signed := h.sign(msg.bytes(), prikey)!
	assert signed.len > 0

	veri := h.verify(msg.bytes(), signed, pubkey)!
	assert true == veri

	signed2 := "hello"
	veri2 := h.verify(msg.bytes(), signed2.bytes(), pubkey)!
	assert false == veri2
}
