import hashlib
import unittest

from baseline_miner import hashing


class HashingTests(unittest.TestCase):
    def test_sha256d_matches_reference(self) -> None:
        data = b"baseline"
        expected = hashlib.sha256(hashlib.sha256(data).digest()).digest()
        self.assertEqual(hashing.sha256d(data), expected)

    def test_difficulty_targets(self) -> None:
        base_target = hashing.compact_to_target(hashing.POW_LIMIT_BITS)
        target1 = int.from_bytes(hashing.difficulty_to_target_bytes(1.0), "big")
        target2 = int.from_bytes(hashing.difficulty_to_target_bytes(2.0), "big")
        self.assertEqual(target1, base_target)
        self.assertLess(target2, target1)

    def test_scan_hashes_matches_reference(self) -> None:
        self.assertTrue(hashing.HAS_SCAN)
        header_prefix = b"\x00" * 76
        target = b"\xff" * 32
        results = hashing.scan_hashes(header_prefix, 0, 5, target)
        self.assertEqual(len(results), 5)
        for nonce, hash_bytes in results:
            expected = hashlib.sha256(
                hashlib.sha256(header_prefix + nonce.to_bytes(4, "little")).digest()
            ).digest()
            self.assertEqual(hash_bytes, expected)


if __name__ == "__main__":
    unittest.main()
