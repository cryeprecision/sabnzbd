import struct
import dataclasses
import pathlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


@dataclasses.dataclass
class SubKeys:
    encrypt: bytes
    id: bytes


@dataclasses.dataclass
class SegmentIds:
    message_id: str
    subject: str
    poster: str


@dataclasses.dataclass
class Nz2FileInfo:
    path: str
    key: bytes
    last_modified: int
    file_size: int
    segment_size: int
    total_segments: int


class ChaCha20Rng:
    def __init__(self, seed: bytes):
        assert len(seed) == 32, "Seed must be 32 bytes long"

        nonce = struct.pack("<L", 0) + b"\0" * 12
        algo = algorithms.ChaCha20(seed, nonce)
        cipher = Cipher(algo, mode=None)

        self.enc = cipher.encryptor()

    def next_u32(self) -> int:
        return int.from_bytes(self.enc.update(b"\0" * 4), "little")

    def _sample_alphanumeric(self, length: int) -> str:
        CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        result = ""
        while len(result) < length:
            index = self.next_u32() >> (32 - 6)
            if index < len(CHARSET):
                result += CHARSET[index]
        return result

    def generate_id(self) -> str:
        result = self._sample_alphanumeric(32)
        result += "@"
        result += self._sample_alphanumeric(8)
        result += "."
        result += self._sample_alphanumeric(3)
        return result


def derive_subkeys(file_key: bytes) -> SubKeys:
    assert len(file_key) == 32, "File key must be 32 bytes long"

    encryption_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"nz2:1.0.0:file",
        info=b"encrypt",
    ).derive(file_key)

    hmac_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"nz2:1.0.0:file",
        info=b"derive",
    ).derive(file_key)

    return SubKeys(encrypt=encryption_key, id=hmac_key)


def _derive_id(id_key: bytes, segment_index: int, kind: str) -> bytes:
    info = struct.pack("<Q", segment_index)
    info += kind.encode("utf-8")

    seed = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"nz2:1.0.0:segment",
        info=info,
    ).derive(id_key)

    rng = ChaCha20Rng(seed)
    return rng.generate_id()


def derive_article_ids(id_key: bytes, segment_index: int) -> SegmentIds:
    assert len(id_key) == 32, "ID key must be 32 bytes long"
    assert segment_index >= 0, "Segment index must be non-negative"

    message_id = _derive_id(id_key, segment_index, "msg")
    subject = _derive_id(id_key, segment_index, "sub")
    poster = _derive_id(id_key, segment_index, "pos")
    return SegmentIds(
        message_id=message_id,
        subject=subject,
        poster=poster,
    )


def derive_assoc_data(file_size: int, segment_size: int, last_modified: int, file_path: str) -> bytes:
    assert file_size > 0, "File size must be positive"
    assert segment_size > 0, "Segment size must be positive"
    assert last_modified >= 0, "Last modified must be non-negative"
    assert not pathlib.Path(file_path).is_absolute(), "File path must be relative"

    assoc_data = struct.pack("<QQQ", file_size, segment_size, last_modified)
    assoc_data += file_path.encode("utf-8")
    return assoc_data


def derive_nonce(segment_index: int) -> bytes:
    assert segment_index >= 0, "Segment index must be non-negative"

    return struct.pack("<QL", segment_index, 0)


def encrypt_segment(
    encrypt_key: bytes,
    segment_data: bytes,
    nonce: bytes,
    assoc_data: bytes,
) -> bytes:
    assert len(segment_data) > 0, "Segment data must be non-empty"
    assert len(nonce) == 12, "Nonce must be 12 bytes long"
    assert len(encrypt_key) == 32, "Encryption key must be 32 bytes long"

    cipher = ChaCha20Poly1305(key=encrypt_key)
    # The tag is appended to the ciphertext, which fits the specification
    # https://cryptography.io/en/46.0.3/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305.encrypt
    ciphertext_with_tag = cipher.encrypt(
        nonce=nonce,
        data=segment_data,
        associated_data=assoc_data,
    )
    return ciphertext_with_tag


def decrypt_segment(
    encrypt_key: bytes,
    encrypted_segment: bytes,
    nonce: bytes,
    assoc_data: bytes,
) -> bytes:
    assert len(encrypted_segment) > 16, "Encrypted segment must be non-empty (with tag)"
    assert len(encrypt_key) == 32, "Encryption key must be 32 bytes long"
    assert len(nonce) == 12, "Nonce must be 12 bytes long"

    cipher = ChaCha20Poly1305(key=encrypt_key)
    # Implicitly expects the tag at the end of the ciphertext
    # This is only implied in the documentation
    # https://cryptography.io/en/46.0.3/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305
    cleartext = cipher.decrypt(
        nonce=nonce,
        data=encrypted_segment,
        associated_data=assoc_data,
    )
    return cleartext
