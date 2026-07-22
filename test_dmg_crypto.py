from __future__ import annotations

import hashlib
import hmac
import math
import os
import struct
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:
    TripleDES = algorithms.TripleDES

from dmg_crypto import DmgPasswordError, decrypt_dmg, is_encrypted_dmg


PASSWORD = "测试密码-LocalOnly"


def make_test_dmg(path: Path, plaintext: bytes) -> None:
    block_size = 512
    data_offset = 512
    salt = bytes(range(20))
    blob_iv = bytes(range(8))
    aes_key = bytes(range(32))
    hmac_key = bytes(range(40, 60))

    padder = padding.PKCS7(64).padder()
    keyblob_plain = padder.update(aes_key + hmac_key) + padder.finalize()
    kdf = PBKDF2HMAC(algorithm=hashes.SHA1(), length=24, salt=salt, iterations=1234)
    wrapping_key = kdf.derive(PASSWORD.encode("utf-8"))
    encryptor = Cipher(TripleDES(wrapping_key), modes.CBC(blob_iv)).encryptor()
    keyblob = encryptor.update(keyblob_plain) + encryptor.finalize()

    header = bytearray(264)
    header[:8] = b"encrcdsa"
    struct.pack_into(">I", header, 8, 2)
    struct.pack_into(">I", header, 12, 16)
    struct.pack_into(">I", header, 24, 256)
    struct.pack_into(">I", header, 32, 160)
    struct.pack_into(">I", header, 52, block_size)
    struct.pack_into(">Q", header, 56, len(plaintext))
    struct.pack_into(">Q", header, 64, data_offset)
    struct.pack_into(">I", header, 96, 103)
    struct.pack_into(">I", header, 100, 0)
    struct.pack_into(">I", header, 104, 1234)
    struct.pack_into(">I", header, 108, len(salt))
    header[112 : 112 + len(salt)] = salt
    struct.pack_into(">I", header, 144, len(blob_iv))
    header[148 : 148 + len(blob_iv)] = blob_iv
    struct.pack_into(">I", header, 180, 192)
    struct.pack_into(">I", header, 184, 17)
    struct.pack_into(">I", header, 188, 7)
    struct.pack_into(">I", header, 192, 6)
    struct.pack_into(">I", header, 196, len(keyblob))
    header[200 : 200 + len(keyblob)] = keyblob

    chunks = []
    for chunk_no in range(math.ceil(len(plaintext) / block_size)):
        chunk = plaintext[chunk_no * block_size : (chunk_no + 1) * block_size]
        chunk = chunk.ljust(block_size, b"\0")
        iv = hmac.new(hmac_key, struct.pack(">I", chunk_no), hashlib.sha1).digest()[:16]
        enc = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
        chunks.append(enc.update(chunk) + enc.finalize())

    with path.open("wb") as target:
        target.write(header)
        target.write(bytes(data_offset - len(header)))
        target.write(b"".join(chunks))


class DmgCryptoTests(unittest.TestCase):
    def test_encrypted_dmg_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "encrypted.dmg"
            make_test_dmg(source, bytes(512))
            self.assertTrue(is_encrypted_dmg(source))

    def test_unencrypted_dmg_does_not_request_decryption(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "plain.dmg"
            source.write_bytes(b"koly" + bytes(512))
            self.assertFalse(is_encrypted_dmg(source))

    def test_round_trip_aes256_dmg(self) -> None:
        plaintext = os.urandom(1400) + b"koly" + bytes(508)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "encrypted.dmg"
            output = Path(directory) / "decrypted.dmg"
            make_test_dmg(source, plaintext)
            decrypt_dmg(source, PASSWORD, output)
            self.assertEqual(output.read_bytes(), plaintext)

    def test_wrong_password_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "encrypted.dmg"
            output = Path(directory) / "decrypted.dmg"
            make_test_dmg(source, bytes(512))
            with self.assertRaises(DmgPasswordError):
                decrypt_dmg(source, "wrong", output)

if __name__ == "__main__":
    unittest.main()
