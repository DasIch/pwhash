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
    )
]
