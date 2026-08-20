module jwt

fn test_blake2b() {
	mut h := signing_blake2b

	assert "BLAKE2B" == h.alg()
	assert 32 == h.sign_length()

	msg := "test-data"
	key := "12345678901234567890as1234567890"
	sign := "d40bb120a0915ab65e0051fca93854775bd1380a1fb012ebd5c5df361159937e"

	signed := h.sign(msg.bytes(), key.bytes())!
	assert signed.hex() == sign

	veri := h.verify(msg.bytes(), signed, key.bytes())!
	assert true == veri

	signed2 := "hello"
	veri2 := h.verify(msg.bytes(), signed2.bytes(), key.bytes())!
	assert false == veri2
}