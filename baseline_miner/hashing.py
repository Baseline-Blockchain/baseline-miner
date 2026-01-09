import hashlib

POW_LIMIT_BITS = 0x207FFFFF
MAX_HASH = (1 << 256) - 1

USING_NATIVE = False

try:
    from ._sha256d import sha256d as _native_sha256d

    def sha256d(data: bytes) -> bytes:
        return _native_sha256d(data)

    USING_NATIVE = True
except Exception:

    def sha256d(data: bytes) -> bytes:
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()


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
