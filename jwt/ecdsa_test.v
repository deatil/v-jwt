module jwt

import encoding.hex
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

fn test_es256_check() {
    pub_key := '-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETpIfMi7oTcpgtbeQ0kulzYlAKLQS
t1pfOGUHtHvce8MEssueOxCHWJKql/sJ+JrJSfqOu5AWlDqGqp77ZA7JCw==
-----END PUBLIC KEY-----'
    pri_key := '-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg/DkEwUlK8nWyB30J
RyxjU42bu//wSrGj2szLE/ybKMqgCgYIKoZIzj0DAQehRANCAAROkh8yLuhNymC1
t5DSS6XNiUAotBK3Wl84ZQe0e9x7wwSyy547EIdYkqqX+wn4mslJ+o67kBaUOoaq
nvtkDskL
-----END PRIVATE KEY-----'

	prikey := ecdsa.privkey_from_string(pri_key)!
	pubkey := ecdsa.pubkey_from_string(pub_key)!

	mut h := signing_es256

    msg := "test-data"

	signed := h.sign(msg.bytes(), prikey)!
	assert signed.len > 0

	veri := h.verify(msg.bytes(), signed, pubkey)!
	assert true == veri

	// ========

	signed2 := "c732644e4fa95675537d506001ff690695041db49bfc28bcacf5482af09089bfbfb2fd60c4117589c5b786b31976d8e006e2d3d479e9aca297dda0b5d3df13b2"

	signed2_bytes := hex.decode(signed2)!

	veri2 := h.verify(msg.bytes(), signed2_bytes, pubkey)!
	assert true == veri2

}
