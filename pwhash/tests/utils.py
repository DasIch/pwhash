# coding: utf-8


PBKDF2_TEST_VECTORS = [
    # RFC 6070
    (
        b"password", b"salt", 1, 20,
        {"hmac-sha1": b"0c60c80f961f0e71f3a9b524af6012062fe037a6"}
    ),
    (
        b"password", b"salt", 2, 20,
        {"hmac-sha1": b"ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"}
    ),
    (
        b"password", b"salt", 4096, 20,
        {"hmac-sha1": b"4b007901b765489abead49d926f721d065a429c1"}
    ),
    (
        b"passwordPASSWORDpassword",
        b"saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25,
        {"hmac-sha1": b"3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"}
    ),
    (
        b"pass\0word", b"sa\0lt", 4096, 16,
        {"hmac-sha1": b"56fa6aa75548099dcc37d7f03425e0c3"}
    ),
    (
        b"password", b"salt", 16777216, 20,
        {"hmac-sha1": b"eefe3d61cd4da4e4e9945b3d6ba2158c2634e984"}
    ),
    # RFC draft-josefsson-scrypt-kdf-01 (expires March 28, 2013!)
    (
        b"passwd", b"salt", 1, 64,
        {"hmac-sha256": b"55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"}
    ),
    (
        b"Password", b"NaCl", 80000, 64,
        {"hmac-sha256": b"4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"}
    )
]
