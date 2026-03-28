#!/usr/bin/env python3
"""Minimal cache diagnostic: read one file twice, measure speedup."""
import time, sys, os

path = sys.argv[1] + "/large/100mb.bin"

# Read 1: cold (CJLB cache empty for this file)
t0 = time.perf_counter()
with open(path, "rb") as f:
    data1 = f.read()
cold = time.perf_counter() - t0

# Read 2: warm (same pages should be cached)
t0 = time.perf_counter()
with open(path, "rb") as f:
    data2 = f.read()
warm1 = time.perf_counter() - t0

# Read 3: warm again
t0 = time.perf_counter()
with open(path, "rb") as f:
    data3 = f.read()
warm2 = time.perf_counter() - t0

# Read 4: 64KB chunks (like benchmark does)
t0 = time.perf_counter()
with open(path, "rb") as f:
    while f.read(65536):
        pass
warm_chunked = time.perf_counter() - t0

# Read 5: single f.read() call in one shot
t0 = time.perf_counter()
with open(path, "rb") as f:
    f.read()
warm_oneshot = time.perf_counter() - t0

print(f"File size: {len(data1)} bytes")
print(f"cold:         {cold:.4f}s  ({len(data1)/cold/1e6:.0f} MB/s)")
print(f"warm1:        {warm1:.4f}s  ({len(data1)/warm1/1e6:.0f} MB/s)  speedup={cold/warm1:.1f}x")
print(f"warm2:        {warm2:.4f}s  ({len(data1)/warm2/1e6:.0f} MB/s)  speedup={cold/warm2:.1f}x")
print(f"warm chunked: {warm_chunked:.4f}s  ({len(data1)/warm_chunked/1e6:.0f} MB/s)  speedup={cold/warm_chunked:.1f}x")
print(f"warm oneshot: {warm_oneshot:.4f}s  ({len(data1)/warm_oneshot/1e6:.0f} MB/s)  speedup={cold/warm_oneshot:.1f}x")
assert data1 == data2 == data3, "DATA MISMATCH"
print("data verified OK")
