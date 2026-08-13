## V-jwt 

A JWT (JSON Web Token) library for vlang.


### Env

 - vlang >= 0.5.2


### What the heck is a JWT?

JWT.io has [a great introduction](https://jwt.io/introduction) to JSON Web Tokens.

In short, it's a signed JSON object that does something useful (for example, authentication).  It's commonly used for `Bearer` tokens in Oauth 2.  A token is made of three parts, separated by `.`'s.  The first two parts are JSON objects, that have been [base64url](https://datatracker.ietf.org/doc/html/rfc4648) encoded.  The last part is the signature, encoded the same way.

The first part is called the header.  It contains the necessary information for verifying the last part, the signature.  For example, which encryption method was used for signing and what key was used.

The part in the middle is the interesting bit.  It's called the Claims and contains the actual stuff you care about.  Refer to [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) for information about reserved keys and the proper way to add your own.


### What's in the box?

This library supports the parsing and verification as well as the generation and signing of JWTs.  Current supported signing algorithms are HMAC SHA, RSA, RSA-PSS, and ECDSA, though hooks are present for adding your own.


### Adding v-jwt as a dependency

Add the dependency to your project:

```bash
v install deatil.vjwt
```

or 

```bash
v install --git https://github.com/deatil/v-jwt
```

The `v-jwt` can be imported in your application with:

```v
import deatil.vjwt.jwt
```


### Get Starting

~~~v
module main

import deatil.vjwt.jwt

fn main() {
    mut claims := map[string]string{}
    claims["aud"] = "example.com"
    claims["iat"] = "foo"

    key := "test-key"

    mut s := jwt.signing_method_hs256.new()
    token_string := s.sign(claims, key.bytes())!
    
    // output: 
    // make jwt: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJleGFtcGxlLmNvbSIsImlhdCI6ImZvbyJ9.50cze1sslhuKh5-sXLoMOjVj6PmOBR9QGJyqzugBiig
    println("make jwt: ${token_string}")

    // =========

    mut p := jwt.signing_method_hs256.new()
    parsed := p.parse(token_string, key.bytes())!
    
    // output: 
    // claims aud: example.com
    claims2 := parsed.get_claims()!
    claims21 := claims2.as_map_of_strings()
    println("claims aud: ${claims21["aud"]}")
}
~~~


### Token Validator

~~~v
module main

import time
import deatil.vjwt.jwt

fn main() {
    token_string := "eyJ0eXAiOiJKV0UiLCJhbGciOiJFUzI1NiIsImtpZCI6ImtpZHMifQ.eyJpc3MiOiJpc3MiLCJpYXQiOjE1Njc4NDIzODgsImV4cCI6MTc2Nzg0MjM4OCwiYXVkIjoiZXhhbXBsZS5jb20iLCJzdWIiOiJzdWIiLCJqdGkiOiJqdGkgcnJyIiwibmJmIjoxNTY3ODQyMzg4fQ.dGVzdC1zaWduYXR1cmU"

    token := jwt.Token.from_string(token_string)

    validator := jwt.Validator.new(token)

    // validator.with_leeway(3);

    // output: 
    // hasBeenIssuedBy: true
    status := validator.has_been_issued_by(["iss"])
    println("hasBeenIssuedBy: ${status}");

    // now := time.now().unix()

    // have functions:
    // validator.has_been_issued_by(["iss"]) // iss
    // validator.is_related_to(["sub"]) // sub
    // validator.is_identified_by("jti rrr") // jti
    // validator.is_permitted_for(["example.com"]) // audience
    // validator.has_been_issued_before(now) // iat, now is time timestamp
    // validator.is_minimum_time_before(now) // nbf, now is time timestamp
    // validator.is_expired(now) // exp, now is time timestamp
}
~~~


### Signing Methods

The JWT library have signing methods:

 - `ES256`: jwt.signing_method_es256
 - `ES384`: jwt.signing_method_es384
 - `ES512`: jwt.signing_method_es512
 - `ES256K`: jwt.signing_method_es256k
 
 - `EdDSA`: jwt.signing_method_eddsa
 - `ED25519`: jwt.signing_method_ed25519

 - `HSHA1`: jwt.signing_method_hsha1
 - `HS224`: jwt.signing_method_hs224
 - `HS256`: jwt.signing_method_hs256
 - `HS384`: jwt.signing_method_hs384
 - `HS512`: jwt.signing_method_hs512

 - `BLAKE2B`: jwt.signing_method_blake2b

 - `none`: jwt.signing_method_none


### Sign PublicKey

ECDSA PublicKey:
~~~v
import crypto.ecdsa
import deatil.vjwt.jwt

// generate public key
pubkey, prikey := ecdsa.generate_key(nid: .prime256v1)! // p256 PublicKey
pubkey, prikey := ecdsa.generate_key(nid: .secp384r1)! // p384 PublicKey
pubkey, prikey := ecdsa.generate_key(nid: .secp521r1)! // p521 PublicKey
pubkey, prikey := ecdsa.generate_key(nid: .secp256k1)! // s256k1 PublicKey

// from key pem
prikey := jwt.parse_ecdsa_privatekey_pem(pri_key_pem_str)!
pubkey := jwt.parse_ecdsa_publickey_pem(pub_key_pem_str)!
~~~

EdDSA PublicKey:
~~~v
import crypto.ed25519
import deatil.vjwt.jwt

// generate public key
pubkey, prikey := ed25519.generate_key()!

// from key pem
prikey := jwt.parse_eddsa_privatekey_pem(pri_key_pem_str)!
pubkey := jwt.parse_eddsa_publickey_pem(pub_key_pem_str)!
~~~


### LICENSE

*  The library LICENSE is `Apache2`, using the library need keep the LICENSE.


### Copyright

*  Copyright deatil(https://github.com/deatil).
