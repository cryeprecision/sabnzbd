import sabnzbd.nz2stuff as nz2
from base64 import b64encode, b64decode
import pytest
from cryptography.exceptions import InvalidTag


def test_chacha20_rng_00():
    EXPECTED_00 = [
        0xADE0B876,
        0x385A46EE,
        0x02742D22,
        0x88602327,
    ]

    rng = nz2.ChaCha20Rng(b"\x00" * 32)
    values = []
    values.append(rng.next_u32())

    for _ in range(4096 - 1):
        _ = rng.next_u32()
    values.append(rng.next_u32())

    for _ in range(4096 - 1):
        _ = rng.next_u32()
    values.append(rng.next_u32())

    for _ in range(4096 - 1):
        _ = rng.next_u32()
    values.append(rng.next_u32())

    for value, expected in zip(values, EXPECTED_00):
        assert value == expected, f"Expected 0x{expected:08X}, got 0x{value:08X}"


def test_chacha20_rng_ff():
    EXPECTED_FF = [
        0x4198B8F6,
        0x2AF06BD5,
        0xAF06794C,
        0xE88561B1,
    ]

    rng = nz2.ChaCha20Rng(b"\xff" * 32)
    values = []
    values.append(rng.next_u32())

    for _ in range(4096 - 1):
        _ = rng.next_u32()
    values.append(rng.next_u32())

    for _ in range(4096 - 1):
        _ = rng.next_u32()
    values.append(rng.next_u32())

    for _ in range(4096 - 1):
        _ = rng.next_u32()
    values.append(rng.next_u32())

    for value, expected in zip(values, EXPECTED_FF):
        assert value == expected, f"Expected 0x{expected:08X}, got 0x{value:08X}"


def test_derive_subkeys_00():
    key = b"\x00" * 32
    subkeys = nz2.derive_subkeys(key)
    assert (
        b64encode(subkeys.encrypt).decode()
        == "SXCHftg+g/FdRlZ6AlRRbCEPv16w7tIGXqJn74m2tSA="
    )
    assert (
        b64encode(subkeys.id).decode() == "36/mff1sS26w2W9xIEYQ9IHerhdcbtPFwzGhmc+Koy4="
    )


def test_derive_subkeys_ff():
    key = b"\xff" * 32
    subkeys = nz2.derive_subkeys(key)
    assert (
        b64encode(subkeys.encrypt).decode()
        == "klOlmm52VO59xVaXE0jgc7XQBetYjgz6qfbzY2Sy7Ps="
    )
    assert (
        b64encode(subkeys.id).decode() == "lFlvUluZL/vaueafGGPaPwsJNgXpfZbgYAoc+ktmkDs="
    )


def test_generate_id_00():
    EXPECTED_00 = [
        "rk5KuGzxfjPN9HahvefDoaP7dQs1KRHb@54CdmxNX.aDH",
        "EwY8WaqCIcNpgLEPVbfdr3sOK2RDyRhy@OzToRBF1.pk2",
        "yGoUdIhTCDFYMSLRjEGXmwtLTwjCz5BD@m3Xg4F21.fSB",
        "30SuoDE2uGfuZaeenpLzgOLFBYYvuBGd@wVxg8uYg.CvN",
        "wFXv20LyC2VrxCLKwYfGalM8CWHPeqMg@AV2UZSEv.ieF",
    ]
    rng = nz2.ChaCha20Rng(b"\x00" * 32)
    for i in range(5):
        assert rng.generate_id() == EXPECTED_00[i]


def test_generate_id_ff():
    EXPECTED_FF = [
        "QYwoRsxcKX8odQMV2thkgmPyIyKGFtzU@kAUXh6Hc.tSq",
        "ne7pG9cQTbY4QBN2Z1iv7HCGlRPiNlB8@9gM51E1t.08R",
        "znIb3pt8k3ZxOotxrQCikogccz8Qqmk9@5azUhTFB.hnY",
        "wif3gteK8oqV5vEOdz09LX5IrTdcvvu5@avWh0Ymg.sIM",
        "0h3EdxTT2IxypHc1hJmYNtvJqcXofh9q@nAQAYQ1J.zdh",
    ]
    rng = nz2.ChaCha20Rng(b"\xff" * 32)
    for i in range(5):
        assert rng.generate_id() == EXPECTED_FF[i]


def test_derive_article_ids_00():
    EXPECTED_00 = [
        {
            "msg": "R4NAnuY181vWV0rE2vfggn0hr5ImRWXJ@E5zLU1Pl.jv4",
            "sub": "AoGbuE58MvNvGZoyXrjdvuhIuKsjjEEe@iM8MdKXu.9wX",
            "pos": "I9fkzYaGxXGOkCXl5lrnjQba3vTdPCGF@KoOhI9e0.fCw",
        },
        {
            "msg": "csWNPuAQtp8wsCXxQGltm7X4qZrAm8rv@1XrmNxMN.gXq",
            "sub": "SKoPNIMp03N40b0M095p4yMkxIVGkdUb@I2wvGmeb.uxc",
            "pos": "6VMn8QfH1PLin2tQYWo1kAABAN6R9Qc8@LwDEWPAo.4m6",
        },
        {
            "msg": "coyFwwSj4BHyFYyyKWEy7dSCLytpEj7D@kEv5uABo.hFw",
            "sub": "VAYhfcOPFcFCZ0REsXYzwB3O74qW6ime@oZODtXU3.HO0",
            "pos": "APUF2MBQkRewJn6qqMtRC2PpWdYYB0wq@Ko7tu2GQ.mM0",
        },
        {
            "msg": "EzT1ZHu8LxP6LRKsfFxd5xP52HhtUTC2@gINwjMrn.ZeC",
            "sub": "nnsWRGKrtAJU7YpjYewPHlhOW5wbckFB@vdlxirvr.LQF",
            "pos": "pJJnt3ypPgLXwLLS7seHUW9FZhxsyCb6@Ib27yxsU.Ukr",
        },
        {
            "msg": "zEvYtgoNFmfI4jTDbOGsi2LNW2no5R1q@NC5GW8mP.74u",
            "sub": "PTny0GQtsdt4DRQSyqSpgfBdxx4wxudi@GK485qeR.H5e",
            "pos": "lhnBpTIliPunTF0gMXTNYJRn2NYT2LsD@wY17YfBp.Jfr",
        },
    ]

    for segment_index in range(5):
        key = b"\x00" * 32
        article_ids = nz2.derive_article_ids(key, segment_index)
        assert article_ids.message_id == EXPECTED_00[segment_index]["msg"]
        assert article_ids.subject == EXPECTED_00[segment_index]["sub"]
        assert article_ids.poster == EXPECTED_00[segment_index]["pos"]


def test_derive_article_ids_ff():
    EXPECTED_FF = [
        {
            "msg": "l4qmBVuaUtosiHJDIkVFfNjtabtzfzgv@zmqxYgya.uY4",
            "sub": "0WisDbzc3Dhr6KQEhpF16Q0XNAfTpNNI@sByUXNzQ.v4C",
            "pos": "5U7mXSmxAG7nQoBPKOcy1iGAR15uodtW@Iqxm78W2.x4r",
        },
        {
            "msg": "Z1tPWZzIzTb5KdVoLu3vZuj4WoB1e00b@Upw6d0hM.2BS",
            "sub": "xp6i9arqg8HXItIsxqrDuUoISscfsmbT@lInB7CgY.VOm",
            "pos": "ggZQcMIPthnlr0GqGkJOXOOUJ0oe6Xyn@tWWvXlIi.lqM",
        },
        {
            "msg": "uSbrAmoj6APfldfgWYiGPaZG7alUgHz3@xxyG61O7.HMl",
            "sub": "mqL7UnM8zoUHbhyInjsWGWu5ljIzLIN8@GujHoMtE.fcJ",
            "pos": "brxnLUXAXG6VQnayEXvXKZ2zf8LxfTtV@tirWogbV.bxa",
        },
        {
            "msg": "Q16sTds3rUZuerrtUHQnBA0JYA0FRQpb@Sv8rY838.2Bg",
            "sub": "oTnMMMjDULAuJ9kzfZdpK60erLkf15mh@X2AHrU7B.Icq",
            "pos": "eHYrYoSz3SAweM80pA0rX2mugs47IKsL@UITdLv1J.OCU",
        },
        {
            "msg": "7l65irxQhCn5v4LBf2kHrru38wYz0mp1@TyC7hxEE.ZGz",
            "sub": "VFB4LLok9VegXeBRreBFrpb5DGIPmUw6@BeGt63hg.Mkj",
            "pos": "bsiP1DivzMqLaBnIL4V8cQ6pnKL0Sj52@mkEqUpK3.UtK",
        },
    ]

    for segment_index in range(5):
        key = b"\xff" * 32
        article_ids = nz2.derive_article_ids(key, segment_index)
        assert article_ids.message_id == EXPECTED_FF[segment_index]["msg"]
        assert article_ids.subject == EXPECTED_FF[segment_index]["sub"]
        assert article_ids.poster == EXPECTED_FF[segment_index]["pos"]


PLAINTEXT_0 = b"TempleOS"
CIPHERTEXT_0 = "y2KKzjk0dykOgEXVeAkwA0ZLjvN46i1L"

PLAINTEXT_1 = "🏆".encode("utf-8")
CIPHERTEXT_1 = "tm95ac9OU4HG1uDROOGxRPoK4uE="

ASSOC_DATA = nz2.derive_assoc_data(
    file_size=12,
    segment_size=8,
    last_modified=420,
    file_path="foo/bar/cool.hc",
)
KEY = b"\x00" * 32


def test_encrypt_segment():
    ciphertext_0 = nz2.encrypt_segment(
        KEY, PLAINTEXT_0, nz2.derive_nonce(0), ASSOC_DATA
    )
    assert b64encode(ciphertext_0).decode() == CIPHERTEXT_0

    ciphertext_1 = nz2.encrypt_segment(
        KEY, PLAINTEXT_1, nz2.derive_nonce(1), ASSOC_DATA
    )
    assert b64encode(ciphertext_1).decode() == CIPHERTEXT_1


def test_decrypt_segment():
    plaintext_0 = nz2.decrypt_segment(
        KEY, b64decode(CIPHERTEXT_0), nz2.derive_nonce(0), ASSOC_DATA
    )
    assert plaintext_0 == PLAINTEXT_0

    plaintext_1 = nz2.decrypt_segment(
        KEY, b64decode(CIPHERTEXT_1), nz2.derive_nonce(1), ASSOC_DATA
    )
    assert plaintext_1 == PLAINTEXT_1


def test_decrypt_segment_wrong_index():
    with pytest.raises(InvalidTag):
        nz2.decrypt_segment(
            KEY, b64decode(CIPHERTEXT_0), nz2.derive_nonce(1), ASSOC_DATA
        )
    with pytest.raises(InvalidTag):
        nz2.decrypt_segment(
            KEY, b64decode(CIPHERTEXT_1), nz2.derive_nonce(0), ASSOC_DATA
        )


def test_decrypt_segment_wrong_assoc_data():
    wrong_assoc_data = nz2.derive_assoc_data(
        file_size=12,
        segment_size=8,
        last_modified=420,
        file_path="foo/bar/cool.exe",
    )
    with pytest.raises(InvalidTag):
        nz2.decrypt_segment(
            KEY, b64decode(CIPHERTEXT_0), nz2.derive_nonce(0), wrong_assoc_data
        )
    with pytest.raises(InvalidTag):
        nz2.decrypt_segment(
            KEY, b64decode(CIPHERTEXT_1), nz2.derive_nonce(1), wrong_assoc_data
        )
