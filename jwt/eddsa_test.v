module jwt

import crypto.ed25519

fn test_eddsa() {
	mut h := signing_eddsa

	assert "EdDSA" == h.alg()
	assert 64 == h.sign_length()

	pubkey, prikey := ed25519.generate_key()!

    msg := "test-data"

	signed := h.sign(msg.bytes(), prikey)!
	assert signed.len > 0

	veri := h.verify(msg.bytes(), signed, pubkey)!
	assert true == veri

	signed2 := "hello"
	veri2 := h.verify(msg.bytes(), signed2.bytes(), pubkey)!
	assert false == veri2
}