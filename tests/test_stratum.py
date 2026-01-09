import unittest

from baseline_miner.stratum import StratumClient


class StratumParseTests(unittest.TestCase):
    def test_parse_notify(self) -> None:
        client = StratumClient("127.0.0.1", 0)
        client.extranonce1 = bytes.fromhex("aabbccdd")
        branch = bytes(range(32))
        params = [
            "1",
            "00" * 32,
            "010203",
            "040506",
            [branch[::-1].hex()],
            "00000001",
            "207fffff",
            "5f5e1000",
            True,
        ]
        job = client._parse_notify(params)
        self.assertIsNotNone(job)
        assert job is not None
        self.assertEqual(job.job_id, "1")
        self.assertEqual(job.prev_hash_le, bytes.fromhex("00" * 32)[::-1])
        self.assertEqual(job.extranonce1, client.extranonce1)
        self.assertEqual(job.version, 1)
        self.assertEqual(job.bits, 0x207FFFFF)
        self.assertEqual(job.merkle_branches_le[0], branch)
        self.assertTrue(job.clean)


if __name__ == "__main__":
    unittest.main()
