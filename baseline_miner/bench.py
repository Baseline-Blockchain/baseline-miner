import argparse
import multiprocessing as mp
import os
import time

from .hashing import BACKEND, scan_hashes, sha256d

BATCH_SIZE = 10000
DEFAULT_SECONDS = 10.0
DEFAULT_DATA_SIZE = 80


def _worker(stop: mp.Event, counter: mp.Value, data: bytes, mode: str) -> None:
    local = 0
    nonce = 0
    header_prefix = b""
    target = b""
    if mode == "scan":
        header_prefix = os.urandom(76)
        target = b"\x00" * 32
    while not stop.is_set():
        if mode == "scan":
            scan_hashes(header_prefix, nonce, BATCH_SIZE, target)
            nonce = (nonce + BATCH_SIZE) & 0xFFFFFFFF
            local += BATCH_SIZE
        else:
            sha256d(data)
            local += 1
        if local >= BATCH_SIZE:
            with counter.get_lock():
                counter.value += local
            local = 0
    if local:
        with counter.get_lock():
            counter.value += local


def main() -> None:
    parser = argparse.ArgumentParser(description="Baseline miner hashing benchmark")
    parser.add_argument("--seconds", type=float, default=DEFAULT_SECONDS)
    parser.add_argument("--threads", type=int, default=os.cpu_count() or 1)
    parser.add_argument("--mode", choices=["scan", "sha256d"], default="scan")
    parser.add_argument("--data-size", type=int, default=DEFAULT_DATA_SIZE)
    args = parser.parse_args()

    data_size = max(1, args.data_size)
    payload = os.urandom(data_size)

    ctx = mp.get_context("spawn")
    stop_event = ctx.Event()
    counters: list[mp.Value] = []
    processes: list[mp.Process] = []

    for _ in range(max(1, args.threads)):
        counter = ctx.Value("Q", 0)
        proc = ctx.Process(
            target=_worker,
            args=(stop_event, counter, payload, args.mode),
            daemon=True,
        )
        proc.start()
        counters.append(counter)
        processes.append(proc)

    start = time.monotonic()
    time.sleep(max(0.1, args.seconds))
    stop_event.set()
    for proc in processes:
        proc.join()
    elapsed = max(0.001, time.monotonic() - start)
    total = sum(counter.value for counter in counters)
    rate = total / elapsed

    print(f"Backend: {BACKEND}")
    print(f"Threads: {len(processes)}")
    print(f"Mode: {args.mode}")
    if args.mode != "scan":
        print(f"Data size: {data_size} bytes")
    print(f"Total hashes: {total}")
    print(f"Elapsed: {elapsed:.2f}s")
    print(f"Hashrate: {rate:.2f} H/s")


if __name__ == "__main__":
    main()
