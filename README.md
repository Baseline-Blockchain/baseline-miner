# Baseline Cash Miner

Open source Stratum miner for Baseline Cash pools, optimized for CPU and GPU throughput.

## Features
- Baseline Cash Stratum client (subscribe/authorize/notify)
- Multi-process SHA256d and SHA256t CPU miner (one worker per process)
- **GPU mining support via OpenCL** (AMD, NVIDIA, Intel, Apple Silicon)
- C SHA256d and SHA256t backend (portable by default; optimized scan path)
- Vardiff `mining.set_difficulty` support
- Clean job handling and share validation

## Requirements
- Python 3.9+
- A C compiler (builds the portable hashing extension)
- OpenCL runtime and drivers (for GPU mining)

## Install
```
git clone https://github.com/Baseline-Blockchain/baseline-miner
cd baseline-miner
python -m venv .venv
. .venv/bin/activate
pip install -e .
```

### Optional: CPU-specific build flags
By default the extension is built in a portable mode (safe to run on other machines).

To squeeze extra performance on the machine you build on, set `BASELINE_MINER_NATIVE=1` to enable CPU-specific compiler flags:

PowerShell (Windows):
```
$env:BASELINE_MINER_NATIVE="1"
pip install -e .
```

bash/zsh (Linux/macOS):
```
BASELINE_MINER_NATIVE=1 pip install -e .
```

Note: CPU-specific builds may crash with `Illegal instruction` if you copy the wheel to an older CPU.

## Usage

### CPU Mining
```
baseline-miner --host pool.baseline.cash --port 3333 --address <BLINE_ADDRESS> --worker rig1
```

### GPU Mining
```
# Mine with default GPU (platform 0, device 0)
baseline-miner --gpu --host pool.baseline.cash --port 3333 --address <BLINE_ADDRESS> --worker rig1

# Mine with all GPUs 
baseline-miner --gpu --host pool.baseline.cash --port 3333 --address <BLINE_ADDRESS> --worker rig1 --gpu-all

SHA256t activation: the miner auto-switches to triple-SHA256 when the pool’s `mining.notify` sets the `pow_sha256t` flag (Baseline node sends this after the network activation height). No CLI flag needed; GPU/CPU paths both follow the job’s algo.

Bench examples:
- CPU scan SHA256d: `baseline-miner-bench --mode scan-d`
- CPU scan SHA256t: `baseline-miner-bench --mode scan-t`
- GPU SHA256t: `baseline-miner-bench --gpu --mode sha256t`

# List available GPU devices
baseline-miner list-devices

# Mine with specific GPU
baseline-miner --gpu --gpu-platform 0 --gpu-device 1 --host 127.0.0.1 --port 3333 --address <BLINE_ADDRESS>
```

### Common options
- `--threads` number of worker processes (CPU mining only, default: CPU count)
- `--gpu` enable GPU mining using OpenCL
- `--gpu-platform` OpenCL platform index (default: 0)
- `--gpu-device` GPU device index within platform (default: 0)
- `--password` stratum password (optional)
- `--stats-interval` seconds between hashrate reports
- `--log-level` debug|info|warning|error

## Benchmark

### CPU Benchmark
```
baseline-miner-bench --seconds 10 --threads 4
```

### GPU Benchmark
```
# List available devices
baseline-miner-bench --list-devices

# Benchmark GPU
baseline-miner-bench --gpu --seconds 10

# Benchmark specific GPU
baseline-miner-bench --gpu --gpu-platform 0 --gpu-device 0 --seconds 10
```

Hashing algorithms:
- Stratum jobs carry `pow_sha256t`; the miner auto-switches between SHA256d and SHA256t.
- Bench defaults: `--mode scan-d` (SHA256d scan). Use `--mode scan-t` (SHA256t scan), `--mode sha256d`, or `--mode sha256t` to benchmark specific paths.

## Tests
```
python -m unittest discover -s tests
```

## License
MIT
