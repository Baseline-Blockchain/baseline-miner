import hashlib

POW_LIMIT_BITS = 0x207FFFFF
MAX_HASH = (1 << 256) - 1

try:
    from ._sha256d import backend as BACKEND_D
    from ._sha256d import scan_hashes as _native_scan_hashes_d
    from ._sha256d import sha256d as _native_sha256d
    from ._sha256t import backend as BACKEND_T
    from ._sha256t import scan_hashes as _native_scan_hashes_t
    from ._sha256t import sha256t as _native_sha256t
except Exception as exc:  # noqa: BLE001
    raise RuntimeError(
        "Native hashing backend is required but could not be loaded. "
        "Reinstall with a working C compiler."
    ) from exc

USING_NATIVE = True
HAS_SCAN_D = True
HAS_SCAN_T = True
# Backward-compat alias retained for callers expecting a single backend name.
BACKEND = "native"


def sha256d(data: bytes) -> bytes:
    return _native_sha256d(data)


def sha256t(data: bytes) -> bytes:
    return _native_sha256t(data)


def scan_hashes(header_prefix: bytes, start_nonce: int, count: int, target: bytes):
    return _native_scan_hashes_d(header_prefix, start_nonce, count, target)


def scan_hashes_sha256t(header_prefix: bytes, start_nonce: int, count: int, target: bytes):
    return _native_scan_hashes_t(header_prefix, start_nonce, count, target)


def sha256t(data: bytes) -> bytes:
    """Triple-SHA256 (software path only)."""
    return hashlib.sha256(hashlib.sha256(hashlib.sha256(data).digest()).digest()).digest()


def compact_to_target(bits: int) -> int:
    exponent = bits >> 24
    mantissa = bits & 0xFFFFFF
    if exponent <= 3:
        target = mantissa >> (8 * (3 - exponent))
    else:
        target = mantissa << (8 * (exponent - 3))
    return target


def target_to_bytes(target: int) -> bytes:
    if target <= 0:
        return (1).to_bytes(32, "big")
    if target > MAX_HASH:
        target = MAX_HASH
    return target.to_bytes(32, "big")


def difficulty_to_target_bytes(difficulty: float) -> bytes:
    if difficulty <= 0:
        difficulty = 1.0
    base = compact_to_target(POW_LIMIT_BITS)
    target = int(base / difficulty)
    return target_to_bytes(target)
