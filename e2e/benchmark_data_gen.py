#!/usr/bin/env python3
"""Generate benchmark test data for CJLB I/O performance testing.

Usage: python3 benchmark_data_gen.py <output_dir>

Creates:
  <output_dir>/small/file_0000.txt .. file_0999.txt  (~100 bytes each)
  <output_dir>/large/100mb.bin                        (exactly 100 MB)
  <output_dir>/medium/batch_00.bin .. batch_09.bin    (10 MB each)
"""
import os
import sys


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <output_dir>", file=sys.stderr)
        sys.exit(1)

    out = sys.argv[1]

    # --- 1000 small files (~100 bytes each) ---
    small_dir = os.path.join(out, "small")
    os.makedirs(small_dir, exist_ok=True)
    print(f"Generating 1000 small files in {small_dir} ...")
    for i in range(1000):
        path = os.path.join(small_dir, f"file_{i:04d}.txt")
        # Deterministic ~100-byte payload
        line = f"config_key_{i:04d} = value_{i * 7:08d}  # comment padding to reach ~100B\n"
        with open(path, "w") as f:
            f.write(line)

    # --- 1 large file (100 MB) ---
    large_dir = os.path.join(out, "large")
    os.makedirs(large_dir, exist_ok=True)
    large_path = os.path.join(large_dir, "100mb.bin")
    print(f"Generating 100 MB file at {large_path} ...")
    target = 100 * 1024 * 1024  # 100 MB
    chunk = 1024 * 1024  # write 1 MB at a time
    state = 42
    with open(large_path, "wb") as f:
        written = 0
        while written < target:
            size = min(chunk, target - written)
            buf = bytearray(size)
            for j in range(size):
                state = (state * 1103515245 + 12345) & 0xFFFFFFFF
                buf[j] = state & 0xFF
            f.write(buf)
            written += size

    # --- 10 medium files (10 MB each) ---
    med_dir = os.path.join(out, "medium")
    os.makedirs(med_dir, exist_ok=True)
    print(f"Generating 10 x 10 MB files in {med_dir} ...")
    med_size = 10 * 1024 * 1024
    for idx in range(10):
        path = os.path.join(med_dir, f"batch_{idx:02d}.bin")
        buf = bytearray(med_size)
        for j in range(med_size):
            state = (state * 1103515245 + 12345) & 0xFFFFFFFF
            buf[j] = state & 0xFF
        with open(path, "wb") as f:
            f.write(buf)

    total_bytes = 1000 * 100 + 100 * 1024 * 1024 + 10 * 10 * 1024 * 1024
    print(f"Done. ~{total_bytes / (1024*1024):.1f} MB total.")


if __name__ == "__main__":
    main()
