"""
Tests based on a throw away ProtonMail account. 

The account has been deleted.
"""

import base64
from protonmail import auth


# AUTH_INFO = {
#     "Code": 1000,
#     "Modulus": "\n-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nc5fkhlTPZsqb/ujEbCVdeUaCQUhDPeVgA5dN3q2jLoQcRrif5/LLp+BosQo4fiVVzZCnGHPGIvFsGf0n/bojbiizO+OfnnuHl+FYK0Qno83FJQ7GXebF4VghRHxEyuokdo4r9QozB9FBBm0M0vcElG0qyDG5p9HP+dXvd7OzcHChPmnJCweALSu7TfUQ4R1ADFVG909XxS9V4G3YEHRo1xGSyzK41YCCG3LYEhwM5I/ygcGLOxNFmGcq63afhVd7JAi2XD0YgzsPm5sM/aAVBd6RvWiKRV8vIDCOMlbax4ZitH4dABKXzO6Tdh9Je5fZcsuYlmN3wScUg6se7QYZsA==\n-----BEGIN PGP SIGNATURE-----\nVersion: OpenPGP.js v1.2.0\nComment: http://openpgpjs.org\n\n\n=twTO\n-----END PGP SIGNATURE-----\n",
#     "ServerEphemeral": "6dIgR0DzZxEUM/6+IJbetYfb/O7IIlhX2Q6kKvkBN0SL1cAWGvY35O6P/x5LDsnh1HmVtMS/LcBAZW5z1c1a4O0XFGbZ5PwSXHbN4VNVnmjxCioT3B2KCj/O1kbLXYsiTPs0zPnEORPguGHy13UeRmZJw4QdiPqIkzTWLdO9k5WuOCqW2WJeLOr5Kt2Rb/GADSnJca9MWo3CkXskEptd0i24QNjKpe47nBA6Ycz10bYPaGkiQ6Mi5eFE3CfEDARkDIPW910+rH3YCMtI1oqLxEGSF9FBaKqg7F8Q07Tf5LW+/8DjYI5AUReendBKyvpcYhVEgapeYYpQIiV/gyp6ew==",
#     "Version": 4,
#     "Salt": "Mc/pO/VHMVR/yw==",
#     "SRPSession": "af3d4b076b002412546ef6a3c6d175c6",
#     "TwoFactor": 0
# }

AUTH_INFO = {
    "Code": 1000,
    "Modulus": "\n-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nc5fkhlTPZsqb/ujEbCVdeUaCQUhDPeVgA5dN3q2jLoQcRrif5/LLp+BosQo4fiVVzZCnGHPGIvFsGf0n/bojbiizO+OfnnuHl+FYK0Qno83FJQ7GXebF4VghRHxEyuokdo4r9QozB9FBBm0M0vcElG0qyDG5p9HP+dXvd7OzcHChPmnJCweALSu7TfUQ4R1ADFVG909XxS9V4G3YEHRo1xGSyzK41YCCG3LYEhwM5I/ygcGLOxNFmGcq63afhVd7JAi2XD0YgzsPm5sM/aAVBd6RvWiKRV8vIDCOMlbax4ZitH4dABKXzO6Tdh9Je5fZcsuYlmN3wScUg6se7QYZsA==\n-----BEGIN PGP SIGNATURE-----\nVersion: OpenPGP.js v1.2.0\nComment: http://openpgpjs.org\n\n\n=twTO\n-----END PGP SIGNATURE-----\n",
    "ServerEphemeral": "6dIgR0DzZxEUM/6+IJbetYfb/O7IIlhX2Q6kKvkBN0SL1cAWGvY35O6P/x5LDsnh1HmVtMS/LcBAZW5z1c1a4O0XFGbZ5PwSXHbN4VNVnmjxCioT3B2KCj/O1kbLXYsiTPs0zPnEORPguGHy13UeRmZJw4QdiPqIkzTWLdO9k5WuOCqW2WJeLOr5Kt2Rb/GADSnJca9MWo3CkXskEptd0i24QNjKpe47nBA6Ycz10bYPaGkiQ6Mi5eFE3CfEDARkDIPW910+rH3YCMtI1oqLxEGSF9FBaKqg7F8Q07Tf5LW+/8DjYI5AUReendBKyvpcYhVEgapeYYpQIiV/gyp6ew==",
    "Version": 4,
    "Salt": "Mc/pO/VHMVR/yw==",
    "SRPSession": "b4bdf2c2df85df1ca350bdeb6aae22f9",
    "TwoFactor": 0
}

AUTH = {
    u'ExpiresIn': 864000,
    u'EventID': u'pLB1Y0liWVtW672yJKUdBtFnVYTdNpzttekr89E1YwUqtOgTxr64XKfcdGyMaFstY8cgMkrU0DE_egT1Nn0izw==',
    u'Code': 1000,
    u'RefreshToken': u'be8a29bf7d3fb241d3f3e0ece3badc4901763efd',
    u'AccessToken': u'-----BEGIN PGP MESSAGE-----\nVersion: ProtonMail\nComment: https://protonmail.com\n\nwcBMAxI6uOpfstdJAQgAk5pn9enCAIeXHf1gSIwnn/UQcodoAmdtxL4s8nIW\nYU7oyHLiuGx4ACytJToFewp37/VuRYg6ioB2fj3F/y3EJmRoc8xu7rHKY3fQ\n2WZj/AtBdVgn0WGv85MzYj3JvufOBnHSZZqoS5bLjRJlCes9ybc+mRM0bkWR\nQlctp+/ndQp6bnLAj6ip1vX+l2Xk5MKa7N5ufwoxoKMgZ5L9J2tNIcGbyJJm\n7JkvdRuNoSABi2qRgD6zmqWouQEr39Ssvufh3Ot7hb6wKBrJuHWhhprDhqNT\nGeARX0ue1fQnTrVuuwxcRfvLpaJSPVmfEr7hLOzTc8RxlMObPV7DN2hSrgRo\nqdJgAdIhV22R01OvjmzLrU+Vwaj6GErQVDkhr/8cKQyjn3HIGToYVTnJdfO+\njtMQxy/H4cDcdyTaOyAQqiNE9fpUVEtqE1ncnE5eGjQC5pvpFmTKXlG/LOxR\nlokzHe4I3L9U\n=3csb\n-----END PGP MESSAGE-----\n',
    u'TokenType': u'Bearer',
    u'ServerProof': u'vRLSwN4dF632mbErIlGDcm77/pS8Jh6MA7k3AGhbTQUguB0sfVjVZo1S/OHdwb3aQMQEYSVDf8ho84sPw9YhEcPdnJ6EdeYSM0IIbj8WreU2LkJUcgXf4X1XmfPU2RjEkLRi3kZmF1/sWiSrjpHg2AroKvdMShOPBpbV0Eb8moljjA06U8HoVTQXMusMEC5U4jbhorTQMZdEWdyl/aGTre2wYa8kMQrwJuuCFuBtiWw8Jii8U0LdP9cak8cmbg+BEoTICZrDpB4s2f6NMK42O1LyRUTWaWTp0zFq7SElrO2Rv5rZGJikbWmgJnM70+OCittaKaiDuXxo77eiS3naOQ==',
    u'EncPrivateKey': u'-----BEGIN PGP PRIVATE KEY BLOCK-----\r\nVersion: OpenPGP.js v2.6.2\r\nComment: https://openpgpjs.org\r\n\r\n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\nXq30U+nHQKC6wuvGAHv56NV4Lvl7gg==\r\n=BhFU\r\n-----END PGP PRIVATE KEY BLOCK-----', u'PrivateKey': u'-----BEGIN PGP PRIVATE KEY BLOCK-----\r\nVersion: OpenPGP.js v2.6.2\r\nComment: https://openpgpjs.org\r\n\r\n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\nXq30U+nHQKC6wuvGAHv56NV4Lvl7gg==\r\n=BhFU\r\n-----END PGP PRIVATE KEY BLOCK-----',
    u'UID': u'905a3470708f34707dcb12000d09e58dd376779b',
    u'Scope': u'full mail self payments keys',
    u'KeySalt': u'ppn7YPT/BHMGmBCs+Lut1w==',
    u'PasswordMode': 1,
    u'Uid': u'905a3470708f34707dcb12000d09e58dd376779b'
}


def test_auth_info():
    from protonmail.client import AuthInfoResponse
    AuthInfoResponse.from_json(**AUTH_INFO)


def test_auth():
    from protonmail.client import AuthResponse
    AuthResponse.from_json(**AUTH)


def test_access_token():
    auth.read_armored(AUTH['AccessToken'])


def test_read_armored():
    """ Make sure the modulus PGP message is read correctly
    
    ProtonMail's response is NOT a valid OpenPGP message!
    
    """
    # ProtonMail's signed modulus message is NOT a valid PGP message
    modulus = auth.read_armored(AUTH_INFO['Modulus'])
    assert modulus == 'c5fkhlTPZsqb/ujEbCVdeUaCQUhDPeVgA5dN3q2jLoQcRrif5/LLp+BosQo4fiVVzZCnGHPGIvFsGf0n/bojbiizO+OfnnuHl+FYK0Qno83FJQ7GXebF4VghRHxEyuokdo4r9QozB9FBBm0M0vcElG0qyDG5p9HP+dXvd7OzcHChPmnJCweALSu7TfUQ4R1ADFVG909XxS9V4G3YEHRo1xGSyzK41YCCG3LYEhwM5I/ygcGLOxNFmGcq63afhVd7JAi2XD0YgzsPm5sM/aAVBd6RvWiKRV8vIDCOMlbax4ZitH4dABKXzO6Tdh9Je5fZcsuYlmN3wScUg6se7QYZsA=='
    # Convert to int
    m = auth.to_bn(base64.b64decode(modulus))
    assert m.bit_length() in (2048, 2047)  # TODO: Why is it -1 ?


def test_hashed_pwd():
    """ Make sure the hashed password matches 
    """
    modulus = base64.b64decode(auth.read_armored(AUTH_INFO['Modulus']))

    # Check salt at different stages
    salt = base64.b64decode(AUTH_INFO['Salt'])
    assert base64.b64encode(salt+'proton') == "Mc/pO/VHMVR/y3Byb3Rvbg=="
    assert '$2y$10$'+auth.bcrypt_encode_base64(salt+'proton') == "$2y$10$Ka9nM9TFKTP9w1/wZ1PtZe"

    # Make sure it's what we expect
    p = auth.hash_password(3, 'protonmail', salt, 'notused', modulus)
    assert base64.b64encode(p) == 'CFX3pYh45jr8hmODKF35o2XsCqj3ZgJT4goskAq59B4XNk6Ut5NYLl74SxOYkncQTTAG5exhgDTiIuKe6KKSh6ORJDBBXgT8WCsR9OgaD5FO9FNwRKIOxDBZqledH/lmFdzg2q56qCcLbAPY7cS0TVJax3khIGcd4eBKvoS5PA1ReoO1p7H5sZzj1xzGpuLTyG/LYruV6mXUuYTKVU+K/ZBTEktYmjDTgczJzkZsXKRD3Bx8g/5SIMkfpSndz/lRJR2rOmeJ5fSiv7esFQ8VIkSLxYOVLcb4y1U95q5luo7e79ZV4wm+IHIg1ywi5zF4SFe5i4cICI94Kzf9OxQntA=='


def test_big_num():
    assert base64.b64encode(auth.from_bn(2)) == 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=='
    assert 2 == auth.to_bn(auth.from_bn(2))


def test_client_proofs():
    b64e, b64d = base64.b64encode, base64.b64decode
    modulus = b64d(auth.read_armored(AUTH_INFO['Modulus']))
    salt = b64d(AUTH_INFO['Salt'])
    hashed_password = auth.hash_password(3, 'protonmail', salt, 'notused', modulus)
    server_ephemeral = b64d(AUTH_INFO['ServerEphemeral'])

    assert b64e(server_ephemeral) == "6dIgR0DzZxEUM/6+IJbetYfb/O7IIlhX2Q6kKvkBN0SL1cAWGvY35O6P/x5LDsnh1HmVtMS/LcBAZW5z1c1a4O0XFGbZ5PwSXHbN4VNVnmjxCioT3B2KCj/O1kbLXYsiTPs0zPnEORPguGHy13UeRmZJw4QdiPqIkzTWLdO9k5WuOCqW2WJeLOr5Kt2Rb/GADSnJca9MWo3CkXskEptd0i24QNjKpe47nBA6Ycz10bYPaGkiQ6Mi5eFE3CfEDARkDIPW910+rH3YCMtI1oqLxEGSF9FBaKqg7F8Q07Tf5LW+/8DjYI5AUReendBKyvpcYhVEgapeYYpQIiV/gyp6ew=="
    assert b64e(auth.from_bn(2)+modulus) == "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHOX5IZUz2bKm/7oxGwlXXlGgkFIQz3lYAOXTd6toy6EHEa4n+fyy6fgaLEKOH4lVc2QpxhzxiLxbBn9J/26I24oszvjn557h5fhWCtEJ6PNxSUOxl3mxeFYIUR8RMrqJHaOK/UKMwfRQQZtDNL3BJRtKsgxuafRz/nV73ezs3BwoT5pyQsHgC0ru031EOEdQAxVRvdPV8UvVeBt2BB0aNcRkssyuNWAghty2BIcDOSP8oHBizsTRZhnKut2n4VXeyQItlw9GIM7D5ubDP2gFQXekb1oikVfLyAwjjJW2seGYrR+HQASl8zuk3YfSXuX2XLLmJZjd8EnFIOrHu0GGbA="
    multiplier = auth.hash(auth.from_bn(2)+modulus)
    assert b64e(multiplier) == "DpI3RvLj80Kbb95hfNyYyS96MHVVNaoQv2zZQLgAihr7X8B/K7qy+kI+CmqAruoODpNxovaDo65FhoO3+KC1b0G++O7Ej5o03UEZWsAQ9NJ5AB6qE0dPJnxKRWvcJzXrZ4tkjTEp0MfMUo0Bw+qOrelOp6hLaQaD67bZHoJmyenuv0ApYgdwy6Cux05Xmf47FgNcW0t1v4XNU9EyfzC9mqZkxhbQq9roVleDtTYZESkl1DrsVN95LCc6VncmeNX9bfA1O8w897GHQLP85kNZfkmFkJb2n0BYX6JqDLD/aCkT80G4P3jx8DFXQrGsvqN6VLO6x6FLf+Y2NyGNG3Q/wA=="

    multiplier = auth.from_bn(auth.mod_reduce(auth.to_bn(multiplier), auth.to_bn(modulus)))
    assert b64e(multiplier) == "m/pSv50UjXj/cPWcD7c7UOn37iwS+MSvu9WLYgpdW5beGQjgQ8fmUmLVWF9IMMW5QALKiYO9gL3YbIaP++WRARkLvQsl8R6tRWDALnzpUAW02g/ktWCJRCMpAe+XXUrG8fw4mCb2yPaKTCD18PKJGXwk33aSwTSz8eDpps6yWHlNgddfVgDwnXXzeVlGuOD7Ca4VZPsd+lV4c2NabrxUw5TS+uMX1llmO+WqohoNLZkyUnlgGcw0lL8PawCH8n2CSeh/3o4kdHZ4pRfw6aJDeWvz0i1sWuEoP3Lc2VkloaKwPsOaP2ZaJEPDy5FjQwyh4echMT7Uvb4itHVuLm0mEA=="

    g = 2
    p = auth.to_bn(modulus)
    hpw = auth.to_bn(hashed_password)
    m = auth.to_bn(multiplier)
    # Hard code for test
    client_secret = b64d("xBm+aaHCvnIHupRLuNB33xZdmb1iS1uErD8wyGaRX5IGs1gBXTbINbhJ5qTfydiy1PgVIzsXwfHG7X0MRQ0Ote7mpUE/2J6xPQ9aF09QRbixAHpZ6x+fX1vo4XpXJgBM0YVtA7RF+ln/Dm5vBiW0NQlG6+JpGyKTeUXpQiypgTZOZw0Bonvo8z/uwAlKLr3c2q+hVClK7+WcbF5UdC3ijddAtV5UIrUei9iaL91k5Dq+hxw76jJAme8w9Qz8NPxc3t0JDdw4eyqUMNwP1PIzlbvtmn6BkbTGBFOdNfQYg6oYwh93ESAnVzL1p/nrgf89ch4kohjIGDgXqnQEvVcC7g==")

    client_ephemeral = auth.from_bn(pow(g, auth.to_bn(client_secret), p))
    assert b64e(client_ephemeral) == "XTaTsmCVqIns4E8dmMNOHpGIvh0j6zXD2cFtRKpNaFNV1zgRyo1CtxwcZO1l3sSk6FqhdBpDZrafSoF4mJIlYhrI4pIxvKiTTVWH50pPDRP6pCA64sHsUgKazHGnM09u29FocjqcewN6Oe+ZIm+A8TnssDmGI80XSy1nhbbPcQCn+VeTGR7g2f3l/7AbEMKnzWg3sZ2NAuNSYQaG2Kd211ZuLgEPQzWxPS+8ePACoWYnS3bzDDi8JXEKM6aXIqcY1+WG6Y1mks7k+bLyt62YfuFnjUzygzmXx6cuaw6UHmuHnfoiObDU5qwM+/RPpvvOCQ7pqB3ufvhgpAm+YiSVdg=="

    scrambling_param = auth.hash(client_ephemeral+server_ephemeral)
    assert b64e(scrambling_param) == "rEtrIOzSKNdsdWgrNAShlFA7oj7O1nt6OaDcW0RZqeExwhT2oU72ieaRy+kMFWMXeGPWCMiaueunGX2eJX0a2mSPKkFQsgXF61xeREgrkDTs2UNKSTXMHOZ0xftbCbmp0+nA/P2nv678wpcDJoN8eWEbvBdl8j7sUOIZ9xZcTp934ff9jqCUNc0sRl8122lgIRKkzAKNyeCOsm5eD16NDpCDp1P3VOGPmhz7bGBit5SoT6NImVyi1Y49h/7T9WQ6IG+gFqihbOZjMNR7E8u2Cbj7loiMSmIPvixonPbTgQI/GkQVT3Nu8RkKMg6nvQTArz/YucS6JmRcqMMzcrq9tg=="

    subtracted = auth.to_bn(server_ephemeral) - auth.mod_reduce(pow(g, hpw, p)*m, p)
    assert b64e(auth.from_bn(subtracted)) == "lRcHTWAmTnndNWVYOOqTjN/BXB6JyQNcbHwMiteJ0/Iw50rGSoDUfc9u+ggUDqhlth7n/fAT7ZrVZdgp9VBPfyvsyYX2UsOOs3OfJ7+ZnZ1O9GCLjgOo7zaok88FIcKmnzXRdkB1DBlEdIRvrQjDAsSar/FCbugoCPC/04xBkUYkWAj05O+pdq3NFz6/6O3NF06bCw2k8PlZF3VXs/F3M/7WkY3MFqNDClNFPnJXP1f0MDP8aHbMQ6D4VypASydZepHcubrklb8kB/e+W3I5HWKqgAisMZgw+PQTb+UTFFZxRihtOD1rDuuifnHpNvZIGwVv54DLEcA2RUsg3tiNLg=="
    if subtracted < 0:
        subtracted += p
    assert b64e(auth.from_bn(subtracted)) == "lRcHTWAmTnndNWVYOOqTjN/BXB6JyQNcbHwMiteJ0/Iw50rGSoDUfc9u+ggUDqhlth7n/fAT7ZrVZdgp9VBPfyvsyYX2UsOOs3OfJ7+ZnZ1O9GCLjgOo7zaok88FIcKmnzXRdkB1DBlEdIRvrQjDAsSar/FCbugoCPC/04xBkUYkWAj05O+pdq3NFz6/6O3NF06bCw2k8PlZF3VXs/F3M/7WkY3MFqNDClNFPnJXP1f0MDP8aHbMQ6D4VypASydZepHcubrklb8kB/e+W3I5HWKqgAisMZgw+PQTb+UTFFZxRihtOD1rDuuifnHpNvZIGwVv54DLEcA2RUsg3tiNLg=="

    exponent = (auth.to_bn(scrambling_param) * hpw + auth.to_bn(client_secret))%(p-1)
    assert b64e(auth.from_bn(exponent)) == "sD+rPM/unfrYzwtTbm/sNfaEyaEzwEcTD1Kth6p7sT+0AEYZ8+A1vPrSQ7DjUqmyGlw2KCQk3mZ6iBgjkoPisHxLlZ+xgb/cEgloF8OkBNv/oOckk2wwNW1j2SNyja5H1NBzIQZ+yB2LJdcZVmdy27kbEMGHqYxJ40HAZTNPHhBmcZC9CD/pXQSdvAE2qFTi43xJF3fDWJARTtNDyLUxp4RG33ikYGsNFVML1dUMVhFYSIc914TSZtcITSC1uD1GMAMUMHRGEn8n2lgBXpRBQTNmAVSANnKeJoocIgV1FCGCN1n42YhcGS8HlD30GsKgQR6HqxkbqmSY/+BioZbrQw=="

    shared_session = auth.from_bn(pow(subtracted, exponent, p))
    assert b64e(shared_session) == "MzmNFkOYBsWjwcOXii9mw7vA+Fbot6e581UI8V7QwbTa6gNkpT+p4mQA7CkhCTu9y9KdKvx/Z0xE/aW06R7CLzCjP9oggkEGH32Q5sfhMsdbaaZYUu81Mh9pMyzpvUGADpDBBHZmN1EkYn3By6hbpAmlyloR/uMA3Piev102j5PMnjKXB99Ady7s7HTfCh4IobV4hjPEfvhsFnem+TrNRFvGnPYJ9wJ0paYVgPH5/Fk18zNBRESsdJSReIN8ocEAdT0sRYfF+4C1g6YtRqxszNkCWlAn+hJunR6WFmYkKLMbNkVQLDPgkFek31h0THJNIdpXnL2hxqRsM6Hycli1ng=="


    # Don't randomly gen in the test
    auth.generate_random_bytes = lambda n: client_secret
    proofs = auth.generate_proofs(2048, modulus, hashed_password,
                                  server_ephemeral)

    assert b64e(proofs['client_ephemeral']) == "XTaTsmCVqIns4E8dmMNOHpGIvh0j6zXD2cFtRKpNaFNV1zgRyo1CtxwcZO1l3sSk6FqhdBpDZrafSoF4mJIlYhrI4pIxvKiTTVWH50pPDRP6pCA64sHsUgKazHGnM09u29FocjqcewN6Oe+ZIm+A8TnssDmGI80XSy1nhbbPcQCn+VeTGR7g2f3l/7AbEMKnzWg3sZ2NAuNSYQaG2Kd211ZuLgEPQzWxPS+8ePACoWYnS3bzDDi8JXEKM6aXIqcY1+WG6Y1mks7k+bLyt62YfuFnjUzygzmXx6cuaw6UHmuHnfoiObDU5qwM+/RPpvvOCQ7pqB3ufvhgpAm+YiSVdg=="
    assert b64e(proofs['client_proof']) == "hd3KIdpaF1//ZFchpVDsq9FpW5/XyXALcWfQiZplAmsr704RbbEUb2fa4O+icpPNXgcZeMk63bN9DFQRykoGzjTooiMPobJWHF5JNrHwBhSKNJnCqTCqIrP5vddzMJCE17+C4ITi4QMJOOFcX3SWP0Capm7U18dSQfHDtaTVtdpr+i3zUd+gU4KykQUtjhZ8j/9JAw24bECaQl1gLPuyULpfFaSZc5wzdKdW3hznYX9rQBJAaFSvqRcN06HhsyDxaswTunUbVAlMrTVMl0+L2HPQpAGp2c0e5KGoYDYwDP3+k4Qs/igQIngEu535m6hPTyvL4qqgKxlqErWucjiOAw=="
    assert b64e(proofs['server_proof']) == "PE6/te1IEulNJPsxRxo+g1RI0czOighWhZSHGHE1kojwysj6n/HE1YSkzV9fkWpKFaxWlQbunoeX2rXqbCPnBiUIDWVWc0ps5tB1uRTOuG249mtX+nXPpwTbN85E7NxERv1MBhaluQQ9CZkfa/B90Sjba4i7K3Ln+pYZ24ZXZnqipHixdDees6XS2Y02ZKYDrlNEJiSDXNUVRGlGatHY5halLWMnKe5jLnLfWZuaAvtFg+FOBLk9tqMf+8cohubjavDFv113a8bn+Sqg2R5rx18b3l/tvUCtEKpb8jDNis5D/xCQpHjVwl7+NhMHIWz6Dp0Fi8Mf9RmQRYe3TECc/w=="
