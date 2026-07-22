from __future__ import annotations

import hashlib
import hmac
import math
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, BinaryIO

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:  # cryptography < 43
    TripleDES = algorithms.TripleDES


class DmgError(Exception):
    """Base error for encrypted DMG processing."""


class DmgPasswordError(DmgError):
    """Raised when the passphrase cannot unwrap the DMG keys."""


@dataclass(frozen=True)
class EncryptionHeader:
    version: int
    data_enc_key_bits: int
    hmac_key_bits: int
    block_size: int
    data_size: int
    data_offset: int
    kdf_algorithm: int
    kdf_prng_algorithm: int
    kdf_iterations: int
    kdf_salt: bytes
    blob_iv: bytes
    blob_enc_key_bits: int
    blob_enc_algorithm: int
    blob_enc_padding: int
    blob_enc_mode: int
    encrypted_keyblob: bytes


HEADER_SIZE = 264
ENCRYPTION_MAGIC = b"encrcdsa"
ProgressCallback = Callable[[int, int], None]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from(">I", data, offset)[0]


def _u64(data: bytes, offset: int) -> int:
    return struct.unpack_from(">Q", data, offset)[0]


def is_encrypted_dmg(path: str | Path) -> bool:
    with Path(path).open("rb") as source:
        return source.read(len(ENCRYPTION_MAGIC)) == ENCRYPTION_MAGIC


def read_header(source: BinaryIO) -> EncryptionHeader:
    source.seek(0)
    data = source.read(HEADER_SIZE)
    if len(data) != HEADER_SIZE:
        raise DmgError("文件太小，不是完整的加密 DMG。")
    if data[:8] != ENCRYPTION_MAGIC:
        raise DmgError("该文件不是受支持的加密 DMG（缺少 encrcdsa 文件头）。")

    version = _u32(data, 8)
    data_enc_key_bits = _u32(data, 24)
    hmac_key_bits = _u32(data, 32)
    block_size = _u32(data, 52)
    data_size = _u64(data, 56)
    data_offset = _u64(data, 64)
    kdf_algorithm = _u32(data, 96)
    kdf_prng_algorithm = _u32(data, 100)
    kdf_iterations = _u32(data, 104)
    salt_len = _u32(data, 108)
    iv_len = _u32(data, 144)
    blob_enc_key_bits = _u32(data, 180)
    blob_enc_algorithm = _u32(data, 184)
    blob_enc_padding = _u32(data, 188)
    blob_enc_mode = _u32(data, 192)
    keyblob_len = _u32(data, 196)

    if version != 2:
        raise DmgError(f"暂不支持 DMG 加密头版本 {version}。")
    if data_enc_key_bits not in (128, 256):
        raise DmgError(f"暂不支持 AES-{data_enc_key_bits} 数据加密。")
    if hmac_key_bits <= 0 or hmac_key_bits % 8:
        raise DmgError("DMG 的 HMAC 密钥长度无效。")
    if block_size <= 0 or block_size > 16 * 1024 * 1024 or block_size % 16:
        raise DmgError("DMG 的加密块大小无效。")
    if data_size <= 0 or data_offset < HEADER_SIZE:
        raise DmgError("DMG 的数据范围无效。")
    if (kdf_algorithm, kdf_prng_algorithm) != (103, 0):
        raise DmgError("暂不支持该 DMG 使用的密码派生算法。")
    if not (1 <= kdf_iterations <= 100_000_000):
        raise DmgError("DMG 的密码迭代次数无效。")
    if not (1 <= salt_len <= 32):
        raise DmgError("DMG 的密码盐长度无效。")
    if iv_len != 8:
        raise DmgError("DMG 的 3DES 初始化向量长度无效。")
    if blob_enc_key_bits != 192:
        raise DmgError("暂不支持该 DMG 的密钥包加密长度。")
    if (blob_enc_algorithm, blob_enc_padding, blob_enc_mode) != (17, 7, 6):
        raise DmgError("暂不支持该 DMG 的密钥包加密方式。")
    if not (8 <= keyblob_len <= 64) or keyblob_len % 8:
        raise DmgError("DMG 的加密密钥包长度无效。")

    return EncryptionHeader(
        version=version,
        data_enc_key_bits=data_enc_key_bits,
        hmac_key_bits=hmac_key_bits,
        block_size=block_size,
        data_size=data_size,
        data_offset=data_offset,
        kdf_algorithm=kdf_algorithm,
        kdf_prng_algorithm=kdf_prng_algorithm,
        kdf_iterations=kdf_iterations,
        kdf_salt=data[112 : 112 + salt_len],
        blob_iv=data[148 : 148 + iv_len],
        blob_enc_key_bits=blob_enc_key_bits,
        blob_enc_algorithm=blob_enc_algorithm,
        blob_enc_padding=blob_enc_padding,
        blob_enc_mode=blob_enc_mode,
        encrypted_keyblob=data[200 : 200 + keyblob_len],
    )


def _unwrap_keys(header: EncryptionHeader, password: str) -> tuple[bytes, bytes]:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=24,
        salt=header.kdf_salt,
        iterations=header.kdf_iterations,
    )
    derived_key = kdf.derive(password.encode("utf-8"))
    decryptor = Cipher(TripleDES(derived_key), modes.CBC(header.blob_iv)).decryptor()
    padded_blob = decryptor.update(header.encrypted_keyblob) + decryptor.finalize()

    try:
        unpadder = padding.PKCS7(64).unpadder()
        keyblob = unpadder.update(padded_blob) + unpadder.finalize()
    except ValueError as exc:
        raise DmgPasswordError("密码不正确，无法解锁这个 DMG。") from exc

    aes_len = header.data_enc_key_bits // 8
    hmac_len = header.hmac_key_bits // 8
    if len(keyblob) < aes_len + hmac_len:
        raise DmgPasswordError("密码不正确，解密后的密钥数据无效。")
    return keyblob[:aes_len], keyblob[aes_len : aes_len + hmac_len]


def decrypt_dmg(
    input_path: str | Path,
    password: str,
    output_path: str | Path,
    progress: ProgressCallback | None = None,
) -> EncryptionHeader:
    input_path = Path(input_path)
    output_path = Path(output_path)

    with input_path.open("rb") as source:
        header = read_header(source)
        encrypted_size = math.ceil(header.data_size / header.block_size) * header.block_size
        source.seek(0, 2)
        file_size = source.tell()
        if header.data_offset + encrypted_size > file_size:
            raise DmgError("DMG 的加密数据不完整，文件可能已损坏。")

        aes_key, hmac_key = _unwrap_keys(header, password)
        source.seek(header.data_offset)
        remaining = header.data_size
        chunks = math.ceil(header.data_size / header.block_size)

        with output_path.open("wb") as target:
            for chunk_no in range(chunks):
                encrypted = source.read(header.block_size)
                if len(encrypted) != header.block_size:
                    raise DmgError("读取 DMG 加密数据时意外到达文件末尾。")
                iv = hmac.new(
                    hmac_key, struct.pack(">I", chunk_no), hashlib.sha1
                ).digest()[:16]
                decryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).decryptor()
                plain = decryptor.update(encrypted) + decryptor.finalize()
                write_len = min(remaining, header.block_size)
                target.write(plain[:write_len])
                remaining -= write_len
                if progress and (chunk_no % 128 == 0 or chunk_no + 1 == chunks):
                    progress(chunk_no + 1, chunks)

    return header
