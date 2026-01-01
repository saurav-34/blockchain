"""Backend utility helpers.

This module contains small, general-purpose primitives used by the blockchain
backend (hashing, endian conversions, varints, and merkle tree helpers).
"""

from __future__ import annotations

import hashlib
from math import log

from hashlib import sha256

try:
    from Crypto.Hash import RIPEMD160  # type: ignore
except Exception:  # pragma: no cover
    RIPEMD160 = None

from Blockchain.Backend.core.EllepticCurve.EllepticCurve import BASE58_ALPHABET


def hash256(data: bytes) -> bytes:
    """Return SHA256(SHA256(data))."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def hash160(data: bytes) -> bytes:
    """Return RIPEMD160(SHA256(data))."""
    digest = sha256(data).digest()

    if RIPEMD160 is not None:
        return RIPEMD160.new(digest).digest()

    # Fallback when pycryptodome isn't available.
    try:
        h = hashlib.new("ripemd160")
    except ValueError as exc:  # pragma: no cover
        raise ImportError(
            "RIPEMD160 hash not available: install 'pycryptodome' or enable ripemd160 in OpenSSL"
        ) from exc
    h.update(digest)
    return h.digest()


def bytes_needed(n: int) -> int:
    if n == 0:
        return 1
    return int(log(n, 256)) + 1


def int_to_little_endian(n: int, length: int) -> bytes:
    """Encode integer n as a little-endian byte sequence of given length."""
    return n.to_bytes(length, "little")


def little_endian_to_int(b: bytes) -> int:
    """Decode a little-endian byte sequence into an integer."""
    return int.from_bytes(b, "little")


def decode_base58(s: str) -> bytes:
    """Decode a Base58Check-encoded string and return the payload bytes."""
    num = 0
    for c in s:
        num *= 58
        num += BASE58_ALPHABET.index(c)

    combined = num.to_bytes(25, byteorder="big")
    checksum = combined[-4:]

    if hash256(combined[:-4])[:4] != checksum:
        raise ValueError(f"bad Address {checksum} {hash256(combined[:-4][:4])}")

    return combined[1:-4]


def encode_varint(i: int) -> bytes:
    """Encode an integer as a Bitcoin-style varint."""
    if i < 0xFD:
        return bytes([i])
    if i < 0x10000:
        return b"\xfd" + int_to_little_endian(i, 2)
    if i < 0x100000000:
        return b"\xfe" + int_to_little_endian(i, 4)
    if i < 0x10000000000000000:
        return b"\xff" + int_to_little_endian(i, 8)
    raise ValueError("integer too large: {}".format(i))


def merkle_parent_level(hashes: list[bytes]) -> list[bytes]:
    """Return the next merkle tree level from a list of hashes."""
    if len(hashes) % 2 == 1:
        hashes = hashes + [hashes[-1]]

    parent_level: list[bytes] = []
    for i in range(0, len(hashes), 2):
        parent_level.append(hash256(hashes[i] + hashes[i + 1]))
    return parent_level


def merkle_root(hashes: list[bytes]) -> bytes:
    """Compute the merkle root of a list of hashes."""
    current_level = hashes
    while len(current_level) > 1:
        current_level = merkle_parent_level(current_level)
    return current_level[0]


def target_to_bits(target: int) -> bytes:
    """Convert a target integer into compact bits representation."""
    raw_bytes = target.to_bytes(32, "big")
    raw_bytes = raw_bytes.lstrip(b"\x00")

    if raw_bytes[0] > 0x7F:
        exponent = len(raw_bytes) + 1
        coefficient = b"\x00" + raw_bytes[:2]
    else:
        exponent = len(raw_bytes)
        coefficient = raw_bytes[:3]

    return coefficient[::-1] + bytes([exponent])