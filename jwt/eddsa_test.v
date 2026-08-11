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

fn test_eddsa2() {
    pub_key := '-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAj/CWF9RnNKe/L0jHWHpUICXDowaNYLbj7Ck/wdzTvE4=
-----END PUBLIC KEY-----'
    pri_key := '-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIK3jWwBPmk1J4dynA3CjSfOLP9seazHZYZ6MCqCU+n0f
-----END PRIVATE KEY-----'

	prikey := parse_eddsa_privatekey_pem(pri_key)!
	pubkey := parse_eddsa_publickey_pem(pub_key)!

	mut h := signing_eddsa

    msg := "test-data"

	signed := h.sign(msg.bytes(), prikey)!
	assert signed.len > 0

	veri := h.verify(msg.bytes(), signed, pubkey)!
	assert true == veri
}