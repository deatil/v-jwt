module jwt

fn test_none() {
	mut h := signing_none

	assert "none" == h.alg()
	assert 0 == h.sign_length()

    msg := "test-data"
    key := ""
    sign := ""

	signed := h.sign(msg.bytes(), key.bytes())!
	assert signed.hex() == sign

	veri := h.verify(msg.bytes(), signed, key.bytes())!
	assert true == veri

	signed2 := "hello"
	veri2 := h.verify(msg.bytes(), signed2.bytes(), key.bytes())!
	assert false == veri2
}