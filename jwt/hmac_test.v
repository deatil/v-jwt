module jwt

fn test_hs256() {
	mut h := signing_hs256

	assert "HS256" == h.alg()
	assert 32 == h.sign_length()

    msg := "test-data"
    key := "test-key"
    sign := "21a286fd6fd9f52676007c66d0f883db46d06158c266d33fb537c23bc618e567"

	signed := h.sign(msg.bytes(), key.bytes())!
	assert signed.hex() == sign

	veri := h.verify(msg.bytes(), signed, key.bytes())!
	assert true == veri
}

fn test_hs384() {
	mut h := signing_hs384

	assert "HS384" == h.alg()
	assert 48 == h.sign_length()

    msg := "test-data"
    key := "test-key"
    sign := "7ef9106e87232142b352343c291d323498d8a8426029181ddf61a65d0f1bc2c497c86a1091f66d97c2179a18d6e67bdf"

	signed := h.sign(msg.bytes(), key.bytes())!
	assert signed.hex() == sign

	veri := h.verify(msg.bytes(), signed, key.bytes())!
	assert true == veri
}

fn test_hs512() {
	mut h := signing_hs512

	assert "HS512" == h.alg()
	assert 64 == h.sign_length()

    msg := "test-data"
    key := "test-key"
    sign := "080e166f475f1c5d61f26b94d45a0cd822729a525e3a3865b87cdf58a36f039ea1948735aab3ad5027d553ad06487fb57d3a9034d2861300297d6cebf838f5bf"

	signed := h.sign(msg.bytes(), key.bytes())!
	assert signed.hex() == sign

	veri := h.verify(msg.bytes(), signed, key.bytes())!
	assert true == veri
}

fn test_hs224() {
	mut h := signing_hs224

	assert "HS224" == h.alg()
	assert 28 == h.sign_length()

    msg := "test-data"
    key := "test-key"
    sign := "ed6ef737f62e606c28d27a7c586b23becae7196fd4c7b141b46c9902"

	signed := h.sign(msg.bytes(), key.bytes())!
	assert signed.hex() == sign

	veri := h.verify(msg.bytes(), signed, key.bytes())!
	assert true == veri
}

fn test_hsha1() {
	mut h := signing_hsha1

	assert "HSHA1" == h.alg()
	assert 20 == h.sign_length()

    msg := "test-data"
    key := "test-key"
    sign := "4106aea97422ce36d01edb8deb52a7841f0234e5"

	signed := h.sign(msg.bytes(), key.bytes())!
	assert signed.hex() == sign

	veri := h.verify(msg.bytes(), signed, key.bytes())!
	assert true == veri
}

fn test_hmd5() {
	mut h := signing_hmd5

	assert "HMD5" == h.alg()
	assert 16 == h.sign_length()

    msg := "test-data"
    key := "test-key"
    sign := "e2e8b98014f740a7c2e19152c24534b2"

	signed := h.sign(msg.bytes(), key.bytes())!
	assert signed.hex() == sign

	veri := h.verify(msg.bytes(), signed, key.bytes())!
	assert true == veri
}
