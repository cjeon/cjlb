#!/bin/bash
set -euo pipefail

echo "=== CJLB End-to-End Test ==="
echo ""

# 1. Create test data
echo "--- Creating test data ---"
mkdir -p /test/data/subdir
echo -n "Hello from CJLB!" > /test/data/hello.txt
echo '{"entrypoint": "/usr/bin/python3 /test/test_shim.py /vroot /test/data", "virtual_root": "/vroot"}' > /test/data/configs.json
python3 -c "
import sys
# Generate deterministic pseudo-random data (2 MB)
data = bytearray()
state = 42
for _ in range(2_000_000):
    state = (state * 1103515245 + 12345) & 0xFFFFFFFF
    data.append(state & 0xFF)
sys.stdout.buffer.write(bytes(data))
" > /test/data/large_file.bin
echo -n "nested content" > /test/data/subdir/nested.txt
echo "Test data created:"
echo "  hello.txt: $(wc -c < /test/data/hello.txt) bytes"
echo "  large_file.bin: $(wc -c < /test/data/large_file.bin) bytes"
echo "  subdir/nested.txt: $(wc -c < /test/data/subdir/nested.txt) bytes"
echo "  configs.json: $(wc -c < /test/data/configs.json) bytes"
echo ""

# 2. Pack the test data into an encrypted bundle
echo "--- Packing test data ---"
cat > /tmp/pack_config.json << 'EOCFG'
{"command": "pack", "input_dir": "/test/data", "output_dir": "/test/bundle"}
EOCFG
OUTPUT=$(/test/bin/e2e-helper /tmp/pack_config.json)
KEY_HEX=$(echo "$OUTPUT" | grep "^KEY:" | cut -d: -f2)
BUNDLE_ID_HEX=$(echo "$OUTPUT" | grep "^BUNDLE_ID:" | cut -d: -f2)
echo "KEY: ${KEY_HEX:0:16}..."
echo "BUNDLE_ID: $BUNDLE_ID_HEX"
echo "Bundle contents:"
ls -la /test/bundle/
ls -la /test/bundle/chunks/
echo ""

# 3. Test: Shim direct (LD_PRELOAD into Python)
echo "=== Test 1: Shim direct (LD_PRELOAD into Python) ==="
echo ""

# Create write dir for the shim
mkdir -p /test/write_layer

# Prepare the config blob in the format the shim expects
cat > /tmp/prepare_config.json << EOCFG
{"command": "prepare-config", "key_hex": "$KEY_HEX", "bundle_id_hex": "$BUNDLE_ID_HEX", "bundle_dir": "/test/bundle", "virtual_root": "/vroot", "write_dir": "/test/write_layer", "output": "/test/config_blob"}
EOCFG
/test/bin/e2e-helper /tmp/prepare_config.json

echo "Config blob: $(wc -c < /test/config_blob) bytes"
echo ""

# Launch Python with the shim:
#   FD 200 reads from config_blob file
#   LD_PRELOAD loads the shim .so
# We use a subshell with exec to set up FD 200 before Python starts
echo "Launching Python with LD_PRELOAD..."
(
  exec 200</test/config_blob
  LD_PRELOAD=/test/bin/libcjlb_shim.so \
    python3 /test/test_shim.py /vroot /test/data
) && echo "=== Test 1 PASSED ===" || {
  echo "=== Test 1 FAILED ==="
  echo ""
  echo "This could be due to:"
  echo "  - Shim initialization failure (check config blob format)"
  echo "  - Route table or manifest reading failure"
  echo "  - File decryption failure"
  echo ""
  echo "Trying with RUST_LOG=debug for more info..."
  (
    exec 200</test/config_blob
    RUST_LOG=debug LD_PRELOAD=/test/bin/libcjlb_shim.so \
      python3 -c "print('shim loaded, basic Python works')" 2>&1
  ) || true
  exit 1
}

echo ""

# 4. Test: Bootstrap -> Runtime exec chain (layer test)
echo "=== Test 2: Bootstrap -> Runtime exec chain ==="
echo ""

# Encrypt the runtime binary
cat > /tmp/encrypt_runtime_config.json << EOCFG
{"command": "encrypt-runtime", "key_hex": "$KEY_HEX", "runtime_bin": "/test/bin/cjlb-runtime", "output": "/test/bundle/runtime.enc"}
EOCFG
/test/bin/e2e-helper /tmp/encrypt_runtime_config.json

echo "runtime.enc: $(wc -c < /test/bundle/runtime.enc) bytes"

# Copy bootstrap and shim next to the bundle
cp /test/bin/cjlb-bootstrap /test/bundle/bootstrap
cp /test/bin/libcjlb_shim.so /test/bundle/libcjlb_shim.so

echo "Piping key material to bootstrap..."
# The bootstrap reads 48 bytes from stdin, decrypts runtime.enc, and fexecve's the
# runtime. The runtime reads key material from FD 200, loads the manifest, reads
# configs.json, and execs the entrypoint with LD_PRELOAD pointing to the shim .so
# in the bundle directory.
#
# Full chain: bootstrap -> runtime -> shim (LD_PRELOAD) -> client entrypoint
set +e
(
  cd /test/bundle
  cat > /tmp/pipe_key_config.json << EOCFG
{"command": "pipe-key", "key_hex": "$KEY_HEX", "bundle_id_hex": "$BUNDLE_ID_HEX"}
EOCFG
  /test/bin/e2e-helper /tmp/pipe_key_config.json \
  | ./bootstrap
) 2>&1
EXIT_CODE=$?
set -e

if [ $EXIT_CODE -eq 0 ]; then
  echo "=== Test 2 PASSED ==="
else
  echo "Bootstrap->Runtime->Shim->Client chain exited with code $EXIT_CODE"
  echo "=== Test 2 FAILED ==="
fi

echo ""
echo "=== ALL TESTS COMPLETED ==="

echo ""
echo "========================================="
echo "=== BENCHMARK ==="
echo "========================================="

# Generate benchmark data
echo "--- Generating benchmark data ---"
python3 /test/e2e/benchmark_data_gen.py /test/bench_data

# Pack benchmark data (needs a configs.json in the directory)
echo '{"entrypoint":"python3 /test/e2e/benchmark.py /bench ENCRYPTED","virtual_root":"/bench"}' \
  > /test/bench_data/configs.json

echo "--- Packing benchmark data ---"
cat > /tmp/bench_pack_config.json << 'EOCFG'
{"command": "pack", "input_dir": "/test/bench_data", "output_dir": "/test/bench_bundle"}
EOCFG
BENCH_OUTPUT=$(/test/bin/e2e-helper /tmp/bench_pack_config.json)
BENCH_KEY=$(echo "$BENCH_OUTPUT" | grep "^KEY:" | cut -d: -f2)
BENCH_BID=$(echo "$BENCH_OUTPUT" | grep "^BUNDLE_ID:" | cut -d: -f2)
echo "BENCH KEY: ${BENCH_KEY:0:16}..."
echo "BENCH BUNDLE_ID: $BENCH_BID"

# Prepare shim config for benchmark bundle
mkdir -p /test/bench_write_layer
cat > /tmp/bench_prepare_config.json << EOCFG
{"command": "prepare-config", "key_hex": "$BENCH_KEY", "bundle_id_hex": "$BENCH_BID", "bundle_dir": "/test/bench_bundle", "virtual_root": "/bench", "write_dir": "/test/bench_write_layer", "output": "/test/bench_config_blob"}
EOCFG
/test/bin/e2e-helper /tmp/bench_prepare_config.json

echo ""
echo "--- Cache Diagnostic (isolated) ---"
echo "Unencrypted:"
python3 /test/e2e/cache_diag.py /test/bench_data
echo ""
echo "Encrypted:"
(
  exec 200</test/bench_config_blob
  LD_PRELOAD=/test/bin/libcjlb_shim.so \
    python3 /test/e2e/cache_diag.py /bench
)

# Prepare a no-cache config (budget=1MB, below 64MB floor → need shim change)
cat > /tmp/bench_prepare_nocache.json << EOCFG
{"command": "prepare-config", "key_hex": "$BENCH_KEY", "bundle_id_hex": "$BENCH_BID", "bundle_dir": "/test/bench_bundle", "virtual_root": "/bench", "write_dir": "/test/bench_write_layer", "memory_budget_mb": 1, "output": "/test/bench_config_nocache"}
EOCFG
/test/bin/e2e-helper /tmp/bench_prepare_nocache.json

echo ""
echo "--- Cold Random I/O: Unencrypted vs Encrypted (no cache) ---"
python3 -c "
import os, sys, time, random

data_dir = sys.argv[1]
label = sys.argv[2]
path = os.path.join(data_dir, 'large', '100mb.bin')
block = 4096
file_size = os.path.getsize(path)
rng = random.Random(42)
offsets = [rng.randint(0, file_size - block) for _ in range(10000)]

# Drop OS page cache
try:
    open('/proc/sys/vm/drop_caches','w').write('3')
except: pass

# Cold random reads
t0 = time.perf_counter()
with open(path, 'rb') as f:
    for off in offsets:
        f.seek(off)
        f.read(block)
elapsed = time.perf_counter() - t0
iops = 10000 / elapsed
mbps = 10000 * block / (1024*1024) / elapsed
print(f'{label}: 10K random 4KB reads in {elapsed:.4f}s | {iops:.0f} IOPS | {mbps:.1f} MB/s')
" /test/bench_data "Plain cold" 2>/dev/null

(
  exec 200</test/bench_config_nocache
  LD_PRELOAD=/test/bin/libcjlb_shim.so \
    python3 -c "
import os, sys, time, random

data_dir = sys.argv[1]
label = sys.argv[2]
path = os.path.join(data_dir, 'large', '100mb.bin')
block = 4096
file_size = 100 * 1024 * 1024  # known size
rng = random.Random(42)
offsets = [rng.randint(0, file_size - block) for _ in range(10000)]

# Cold random reads (CJLB cache is tiny — effectively every read is a miss)
t0 = time.perf_counter()
with open(path, 'rb') as f:
    for off in offsets:
        f.seek(off)
        f.read(block)
elapsed = time.perf_counter() - t0
iops = 10000 / elapsed
mbps = 10000 * block / (1024*1024) / elapsed
print(f'{label}: 10K random 4KB reads in {elapsed:.4f}s | {iops:.0f} IOPS | {mbps:.1f} MB/s')
" /bench "Enc cold (no cache)" 2>/dev/null
)

echo ""
echo "--- Overhead Diagnosis ---"
echo "Raw I/O components (no shim):"
python3 /test/e2e/overhead_diag.py /test/bench_bundle plain
echo ""
echo "Encrypted via shim (no cache):"
(
  exec 200</test/bench_config_nocache
  LD_PRELOAD=/test/bin/libcjlb_shim.so \
    python3 /test/e2e/overhead_diag.py /bench encrypted 2>/dev/null
)

echo ""
echo "--- Unencrypted (direct filesystem) ---"
python3 /test/e2e/benchmark.py /test/bench_data UNENCRYPTED

echo ""
echo "--- Encrypted (CJLB shim) ---"
(
  exec 200</test/bench_config_blob
  LD_PRELOAD=/test/bin/libcjlb_shim.so \
    python3 /test/e2e/benchmark.py /bench ENCRYPTED
)

echo ""
echo "--- 4-Way Comparison Matrix ---"
python3 -c "
import json, sys
try:
    with open('/tmp/bench_results_UNENCRYPTED.json') as f:
        p = json.load(f)
    with open('/tmp/bench_results_ENCRYPTED.json') as f:
        e = json.load(f)

    hdr = f\"{'Workload':<24} {'Plain Cold':>12} {'Plain Warm':>12} {'Enc Cold':>12} {'Enc Warm':>12} {'Enc Overhead':>13}\"
    print(hdr)
    print('-' * len(hdr))

    for test in p:
        if test not in e:
            continue
        pc = p[test].get('cold_time', p[test].get('cold_time', 0))
        pw = p[test].get('warm_time', p[test].get('warm_time', 0))
        ec = e[test].get('cold_time', e[test].get('cold_time', 0))
        ew = e[test].get('warm_time', e[test].get('warm_time', 0))
        # Overhead = encrypted warm / unencrypted warm (both cached, fair)
        fair_overhead = ew / pw if pw > 0 else 0
        print(f'{test:<24} {pc:>11.4f}s {pw:>11.4f}s {ec:>11.4f}s {ew:>11.4f}s {fair_overhead:>12.1f}x')

    print()
    print('Enc Overhead = encrypted warm / unencrypted warm (both cached, apples-to-apples)')
except Exception as ex:
    print(f'comparison failed: {ex}', file=sys.stderr)
"

echo ""
echo "=== BENCHMARK COMPLETE ==="
