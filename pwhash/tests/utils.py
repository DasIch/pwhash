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
    # RFC 3962
    (
        b"password", b"ATHENA.MIT.EDUraeburn", 1, 16,
        {"hmac-sha1": b"cdedb5281bb2f801565a1122b2563515"}
    ),
    (
        b"password", b"ATHENA.MIT.EDUraeburn", 1, 32,
        {"hmac-sha1": b"cdedb5281bb2f801565a1122b25635150ad1f7a04bb9f3a333ecc0e2e1f70837"}
    ),
    (
        b"password", b"ATHENA.MIT.EDUraeburn", 2, 16,
        {"hmac-sha1": b"01dbee7f4a9e243e988b62c73cda935d"}
    ),
    (
        b"password", b"ATHENA.MIT.EDUraeburn", 2, 32,
        {"hmac-sha1": b"01dbee7f4a9e243e988b62c73cda935da05378b93244ec8f48a99e61ad799d86"}
    ),
    (
        b"password", b"ATHENA.MIT.EDUraeburn", 1200, 16,
        {"hmac-sha1": b"5c08eb61fdf71e4e4ec3cf6ba1f5512b"}
    ),
    (
        b"password", b"ATHENA.MIT.EDUraeburn", 1200, 32,
        {"hmac-sha1": b"5c08eb61fdf71e4e4ec3cf6ba1f5512ba7e52ddbc5e5142f708a31e2e62b1e13"}
    ),
    (
        b"password", b"\x124VxxV4\x12", 5, 16,
        {"hmac-sha1": b"d1daa78615f287e6a1c8b120d7062a49"}
    ),
    (
        b"password", b"\x124VxxV4\x12", 5, 32,
        {"hmac-sha1": b"d1daa78615f287e6a1c8b120d7062a493f98d203e6be49a6adf4fa574b6e64ee"}
    ),
    (
        b"X" * 64, b"pass phrase equals block size", 1200, 16,
        {"hmac-sha1": b"139c30c0966bc32ba55fdbf212530ac9"}
    ),
    (
        b"X" * 64, b"pass phrase equals block size", 1200, 32,
        {"hmac-sha1": b"139c30c0966bc32ba55fdbf212530ac9c5ec59f1a452f5cc9ad940fea0598ed1"}
    ),
    (
        b"X" * 65, b"pass phrase exceeds block size", 1200, 16,
        {"hmac-sha1": b"9ccad6d468770cd51b10e6a68721be61"}
    ),
    (
        b"X" * 65, b"pass phrase exceeds block size", 1200, 32,
        {"hmac-sha1": b"9ccad6d468770cd51b10e6a68721be611a8b4d282601db3b36be9246915ec82a"}
    ),
    (
        b"\xf0\x9d\x84\x9e", b"EXAMPLE.COMpianist", 50, 16,
        {"hmac-sha1": b"6b9cf26d45455a43a5b8bb276a403b39"}
    ),
    (
        b"\xf0\x9d\x84\x9e", b"EXAMPLE.COMpianist", 50, 32,
        {"hmac-sha1": b"6b9cf26d45455a43a5b8bb276a403b39e7fe37a0c41e02c281ff3069e1e94f52"}
    )
]
