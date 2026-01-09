from dataclasses import dataclass


@dataclass
class MiningJob:
    job_id: str
    prev_hash_le: bytes
    coinb1: bytes
    coinb2: bytes
    merkle_branches_le: list[bytes]
    version: int
    bits: int
    ntime: int
    extranonce1: bytes
    clean: bool


@dataclass
class Share:
    job_id: str
    extranonce2: int
    ntime: int
    nonce: int
    is_block: bool
    hash_hex: str
