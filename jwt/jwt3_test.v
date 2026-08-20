module jwt

import crypto.ecdsa

fn test_signing_method_es256() {
	mut h := signing_method_es256.new()
	assert "ES256" == h.alg()
	assert 64 == h.sign_length()

	mut claims := map[string]JsonAny{}
	claims["aud"] = JsonAny("example.com")
	claims["iat"] = JsonAny("foo")

	pubkey, prikey := ecdsa.generate_key(nid: .prime256v1)!

	token_string := h.sign[map[string]JsonAny](claims, prikey)!
	assert token_string.len > 0

	parsed := h.parse(token_string, pubkey)!

	claims2 := parsed.get_claims()!
	claims21 := claims2.as_map_of_strings()
	assert "example.com" == claims21["aud"]
	assert "foo" == claims21["iat"]
}

fn test_signing_method_es384() {
	mut h := signing_method_es384.new()

	assert "ES384" == h.alg()
	assert 96 == h.sign_length()

	mut claims := map[string]JsonAny{}
	claims["aud"] = JsonAny("example.com")
	claims["iat"] = JsonAny("foo")

	pubkey, prikey := ecdsa.generate_key(nid: .secp384r1)!

	token_string := h.sign[map[string]JsonAny](claims, prikey)!
	assert token_string.len > 0

	parsed := h.parse(token_string, pubkey)!

	claims2 := parsed.get_claims()!
	claims21 := claims2.as_map_of_strings()
	assert "example.com" == claims21["aud"]
	assert "foo" == claims21["iat"]
}

fn test_signing_method_es512() {
	mut h := signing_method_es512.new()

	assert "ES512" == h.alg()
	assert 132 == h.sign_length()

	mut claims := map[string]JsonAny{}
	claims["aud"] = JsonAny("example.com")
	claims["iat"] = JsonAny("foo")

	pubkey, prikey := ecdsa.generate_key(nid: .secp384r1)!

	token_string := h.sign[map[string]JsonAny](claims, prikey)!
	assert token_string.len > 0

	parsed := h.parse(token_string, pubkey)!

	claims2 := parsed.get_claims()!
	claims21 := claims2.as_map_of_strings()
	assert "example.com" == claims21["aud"]
	assert "foo" == claims21["iat"]
}

fn test_signing_method_es256k() {
	mut h := signing_method_es256k.new()
	
	assert "ES256K" == h.alg()
	assert 64 == h.sign_length()

	mut claims := map[string]JsonAny{}
	claims["aud"] = JsonAny("example.com")
	claims["iat"] = JsonAny("foo")

	pubkey, prikey := ecdsa.generate_key(nid: .secp256k1)!

	token_string := h.sign[map[string]JsonAny](claims, prikey)!
	assert token_string.len > 0

	parsed := h.parse(token_string, pubkey)!

	claims2 := parsed.get_claims()!
	claims21 := claims2.as_map_of_strings()
	assert "example.com" == claims21["aud"]
	assert "foo" == claims21["iat"]
}

fn test_signing_method_es256_check() {
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
	token_str := "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIifQ.WDolEPRIhE9t5azDM_iepn9ezk0dIuExOKFYFAdVS1QC3iOyWM__4ZEAiLgCkGuaPo0ftVQCsCYItjKgVZHgGQ"

	prikey := parse_ecdsa_privatekey_pem(pri_key)!
	pubkey := parse_ecdsa_publickey_pem(pub_key)!

	mut h := signing_method_es256.new()

	mut claims := map[string]JsonAny{}
	claims["foo"] = JsonAny("bar")

	token_string := h.sign[map[string]JsonAny](claims, prikey)!
	assert token_string.len > 0

	parsed := h.parse(token_str, pubkey)!

	claims2 := parsed.get_claims()!
	claims21 := claims2.as_map_of_strings()
	assert "bar" == claims21["foo"]

	prikey.free()
	pubkey.free()
}

fn test_signing_method_es384_check() {
	pub_key := '-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEzl47hn4Zf+CcpbMbmhMOH8SDl5XtISQ9
QCTg3AvHtyiUjBuTBoSi0D76NiGQHfSCu28kQK83oM8LTIwJxsxPaCF5wpuyXM7s
l+LET6C/HfkTbXO2VYxC/7K4E1qIVgN7
-----END PUBLIC KEY-----'
	pri_key := '-----BEGIN PRIVATE KEY-----
MIG/AgEAMBAGByqGSM49AgEGBSuBBAAiBIGnMIGkAgEBBDCKkU3/bJJS2nV+u4FS
gCLgcaNaDnyB7sEEhXvCLf4DJiLWplxb/lNdHKtEVbx828OgBwYFK4EEACKhZANi
AATOXjuGfhl/4JylsxuaEw4fxIOXle0hJD1AJODcC8e3KJSMG5MGhKLQPvo2IZAd
9IK7byRArzegzwtMjAnGzE9oIXnCm7JczuyX4sRPoL8d+RNtc7ZVjEL/srgTWohW
A3s=
-----END PRIVATE KEY-----'
	token_str := "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCJ9.eyJmb28iOiJiYXIifQ.GeAljd7NH1LQ363xqAb7G608EvXX3svYTMwjcmEVnTapGF7Y4puGIVW4TeXsMij9646Gi_HJ3ghAqgHvWh5CMyvQFOQThyVy7CVxhtrn3GFgse1Kz8wOd0_X_XtOvCsF"

	prikey := parse_ecdsa_privatekey_pem(pri_key)!
	pubkey := parse_ecdsa_publickey_pem(pub_key)!

	mut h := signing_method_es384.new()

	mut claims := map[string]JsonAny{}
	claims["foo"] = JsonAny("bar")

	token_string := h.sign[map[string]JsonAny](claims, prikey)!
	assert token_string.len > 0

	parsed := h.parse(token_str, pubkey)!

	claims2 := parsed.get_claims()!
	claims21 := claims2.as_map_of_strings()
	assert "bar" == claims21["foo"]

	prikey.free()
	pubkey.free()
}

fn test_signing_method_es512_check() {
	pub_key := '-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB5SlzIESgK4L2JngDSaRUmzpQ+dRq
VP450M4VqKJo7+DE/1K8+LU85DGNYFjSKTBTWCs3M3U+kFnGgr2MfNHzdtAAsGWE
KQ4W+JQKN6yqLz1OcAc8BnzAzF91mGjwoJURLpNZldd0y1ucbL9EmyjqB0LmhokP
FW9ltEEMEvInnLkEKvI=
-----END PUBLIC KEY-----'
	pri_key := '-----BEGIN PRIVATE KEY-----
MIH3AgEAMBAGByqGSM49AgEGBSuBBAAjBIHfMIHcAgEBBEIAyYKP3zmWUSvKgv9B
YFSQ8SNvCUWQ+ac4o8xxVxQ0xJJYi5r86HoOcPafRhA08FpL5QsbH09t7SIb4/u3
SRoaHamgBwYFK4EEACOhgYkDgYYABAHlKXMgRKArgvYmeANJpFSbOlD51GpU/jnQ
zhWoomjv4MT/Urz4tTzkMY1gWNIpMFNYKzczdT6QWcaCvYx80fN20ACwZYQpDhb4
lAo3rKovPU5wBzwGfMDMX3WYaPCglREuk1mV13TLW5xsv0SbKOoHQuaGiQ8Vb2W0
QQwS8iecuQQq8g==
-----END PRIVATE KEY-----'
	token_str := "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzUxMiJ9.eyJmb28iOiJiYXIifQ.AdHc_BALB2aBPnEl0FLQtOLgJLqmbxgF9npNd19TZTYwqHmZZ0_eizbagmjJVxpImzXSi-DYezLQDbwN_4iJrvlxAILX9SSrsHh0zbkJAjMAIJDMkZ7nfR7KgCNqvyT7JgEN41i6juk1n8uP3edFptYa1QxnLEG4v6_-NJdOl1xQVtZA"

	prikey := parse_ecdsa_privatekey_pem(pri_key)!
	pubkey := parse_ecdsa_publickey_pem(pub_key)!

	mut h := signing_method_es512.new()

	mut claims := map[string]JsonAny{}
	claims["foo"] = JsonAny("bar")

	token_string := h.sign[map[string]JsonAny](claims, prikey)!
	assert token_string.len > 0

	parsed := h.parse(token_str, pubkey)!

	claims2 := parsed.get_claims()!
	claims21 := claims2.as_map_of_strings()
	assert "bar" == claims21["foo"]

	prikey.free()
	pubkey.free()
}

fn test_signing_method_es256k_check() {
	pub_key := '-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEy8wuv6+fXodLPLfhxm132y1R8m4dkng7
tHe7N+sULV2Eth6AxEXQfd+E4nuceR21UNCvQKqxiYwCzVwIKcHe/A==
-----END PUBLIC KEY-----'
	pri_key := '-----BEGIN PRIVATE KEY-----
MIGNAgEAMBAGByqGSM49AgEGBSuBBAAKBHYwdAIBAQQgxOKd7ezy1P7xuzAMzj/P
yj7AhgZv09A+vDzHo27pAN2gBwYFK4EEAAqhRANCAATLzC6/r59eh0s8t+HGbXfb
LVHybh2SeDu0d7s36xQtXYS2HoDERdB934Tie5x5HbVQ0K9AqrGJjALNXAgpwd78
-----END PRIVATE KEY-----'
	token_str := "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJmb28iOiJiYXIifQ.Xe92dmU8MrI1d4edE2LEKqSmObZJpkIuz0fERihfn65ikTeeX5zjpyAdlHy9ZSBX8N8sqmJy5fxBTBzV26WvIQ"

	prikey := parse_ecdsa_privatekey_pem(pri_key)!
	pubkey := parse_ecdsa_publickey_pem(pub_key)!

	mut h := signing_method_es256k.new()

	mut claims := map[string]JsonAny{}
	claims["foo"] = JsonAny("bar")

	token_string := h.sign[map[string]JsonAny](claims, prikey)!
	assert token_string.len > 0

	parsed := h.parse(token_str, pubkey)!

	claims2 := parsed.get_claims()!
	claims21 := claims2.as_map_of_strings()
	assert "bar" == claims21["foo"]

	prikey.free()
	pubkey.free()
}


