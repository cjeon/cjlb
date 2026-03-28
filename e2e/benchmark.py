#!/usr/bin/env python3
"""Fair 4-way I/O benchmark: unencrypted disk/memory vs encrypted cold/cached.

Usage: python3 benchmark.py <data_dir> <label>

The script runs each workload in 4 conditions:
  1. Cold (first read after cache drop)
  2. Warm (immediate re-read — OS page cache or CJLB LRU cache)

Both UNENCRYPTED and ENCRYPTED runs produce cold+warm numbers.
The fair comparison matrix is:

  unencrypted cold  vs  encrypted cold   = encryption overhead on disk reads
  unencrypted warm  vs  encrypted warm   = encryption overhead on cached reads
  encrypted cold    vs  encrypted warm   = CJLB cache effectiveness
"""
import json
import os
import random
import sys
import time


def flush_os_caches():
    """Drop OS page cache. Needs root or just silently fails."""
    try:
        with open("/proc/sys/vm/drop_caches", "w") as f:
            f.write("3\n")
    except (PermissionError, FileNotFoundError, OSError):
        pass


def timed_read_all(path, chunk_size=65536):
    """Read entire file in chunks, return (elapsed, total_bytes)."""
    total = 0
    t0 = time.perf_counter()
    with open(path, "rb") as f:
        while True:
            data = f.read(chunk_size)
            if not data:
                break
            total += len(data)
    return time.perf_counter() - t0, total


def timed_random_reads(path, offsets, block=4096):
    """Seek+read at each offset, return elapsed."""
    t0 = time.perf_counter()
    with open(path, "rb") as f:
        for off in offsets:
            f.seek(off)
            f.read(block)
    return time.perf_counter() - t0


def run_workload(name, cold_fn, warm_fn, warm_repeats=3):
    """Run a workload: one cold run, then warm_repeats warm runs."""
    flush_os_caches()
    cold_result = cold_fn()

    warm_results = []
    for _ in range(warm_repeats):
        warm_results.append(warm_fn())

    return cold_result, warm_results


def fmt_mbps(total_bytes, elapsed):
    if elapsed <= 0:
        return "inf"
    return f"{total_bytes / (1024*1024) / elapsed:.0f}"


def fmt_iops(count, elapsed):
    if elapsed <= 0:
        return "inf"
    return f"{count / elapsed:.0f}"


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <data_dir> <label>", file=sys.stderr)
        sys.exit(1)

    data_dir = sys.argv[1]
    label = sys.argv[2]

    large_path = os.path.join(data_dir, "large", "100mb.bin")
    med_dir = os.path.join(data_dir, "medium")
    small_dir = os.path.join(data_dir, "small")
    med_files = [os.path.join(med_dir, f"batch_{i:02d}.bin") for i in range(10)]
    small_files = [os.path.join(small_dir, f"file_{i:04d}.txt") for i in range(1000)]

    file_size = 100 * 1024 * 1024
    rng = random.Random(42)
    random_offsets = [rng.randint(0, file_size - 4096) for _ in range(10000)]

    print(f"=== BENCHMARK: {label} ===")
    print(f"    data_dir: {data_dir}")
    print()
    print(f"{'Workload':<30} {'Cold':>12} {'Warm':>12} {'Cache Speedup':>14}")
    print("-" * 70)

    results = {}

    # --- 1. Sequential 100MB read (64KB chunks) ---
    def seq_cold():
        return timed_read_all(large_path)
    def seq_warm():
        return timed_read_all(large_path)

    cold, warms = run_workload("seq_100mb", seq_cold, seq_warm)
    cold_t, total_b = cold
    warm_t = sum(w[0] for w in warms) / len(warms)
    speedup = cold_t / warm_t if warm_t > 0 else 0

    print(f"{'seq 100MB (64KB chunks)':<30} {fmt_mbps(total_b, cold_t)+' MB/s':>12} "
          f"{fmt_mbps(total_b, warm_t)+' MB/s':>12} {speedup:>13.1f}x")
    results["seq_100mb"] = {
        "cold_time": cold_t, "cold_mbps": float(fmt_mbps(total_b, cold_t)),
        "warm_time": warm_t, "warm_mbps": float(fmt_mbps(total_b, warm_t)),
        "cache_speedup": speedup,
    }

    # --- 2. Bulk 10x10MB sequential ---
    def bulk_cold():
        t0 = time.perf_counter()
        total = 0
        for p in med_files:
            with open(p, "rb") as f:
                total += len(f.read())
        return time.perf_counter() - t0, total
    def bulk_warm():
        return bulk_cold()  # same operation, cache should be hot

    cold, warms = run_workload("bulk_10x10mb", bulk_cold, bulk_warm)
    cold_t, total_b = cold
    warm_t = sum(w[0] for w in warms) / len(warms)
    speedup = cold_t / warm_t if warm_t > 0 else 0

    print(f"{'bulk 10x10MB':<30} {fmt_mbps(total_b, cold_t)+' MB/s':>12} "
          f"{fmt_mbps(total_b, warm_t)+' MB/s':>12} {speedup:>13.1f}x")
    results["bulk_10x10mb"] = {
        "cold_time": cold_t, "warm_time": warm_t,
        "cold_mbps": float(fmt_mbps(total_b, cold_t)),
        "warm_mbps": float(fmt_mbps(total_b, warm_t)),
        "cache_speedup": speedup,
    }

    # --- 3. Random 4KB reads (10K ops) ---
    def rand_cold():
        return timed_random_reads(large_path, random_offsets), len(random_offsets)
    def rand_warm():
        return timed_random_reads(large_path, random_offsets), len(random_offsets)

    cold, warms = run_workload("random_4kb", rand_cold, rand_warm)
    cold_t, n_ops = cold
    warm_t = sum(w[0] for w in warms) / len(warms)
    speedup = cold_t / warm_t if warm_t > 0 else 0

    print(f"{'random 4KB (10K ops)':<30} {fmt_iops(n_ops, cold_t)+' IOPS':>12} "
          f"{fmt_iops(n_ops, warm_t)+' IOPS':>12} {speedup:>13.1f}x")
    results["random_4kb"] = {
        "cold_time": cold_t, "warm_time": warm_t,
        "cold_iops": float(fmt_iops(n_ops, cold_t)),
        "warm_iops": float(fmt_iops(n_ops, warm_t)),
        "cache_speedup": speedup,
    }

    # --- 4. 1000 small file reads ---
    def small_cold():
        t0 = time.perf_counter()
        total = 0
        for p in small_files:
            with open(p, "rb") as f:
                total += len(f.read())
        return time.perf_counter() - t0, len(small_files), total
    def small_warm():
        return small_cold()

    cold, warms = run_workload("small_1000", small_cold, small_warm)
    cold_t, count, total_b = cold
    warm_t = sum(w[0] for w in warms) / len(warms)
    speedup = cold_t / warm_t if warm_t > 0 else 0

    print(f"{'small files (1000)':<30} {fmt_iops(count, cold_t)+' files/s':>12} "
          f"{fmt_iops(count, warm_t)+' files/s':>12} {speedup:>13.1f}x")
    results["small_1000"] = {
        "cold_time": cold_t, "warm_time": warm_t,
        "cold_fps": float(fmt_iops(count, cold_t)),
        "warm_fps": float(fmt_iops(count, warm_t)),
        "cache_speedup": speedup,
    }

    # --- 5. Directory listing (1000 entries, 100 iterations) ---
    def listdir_cold():
        t0 = time.perf_counter()
        for _ in range(100):
            os.listdir(small_dir)
        return time.perf_counter() - t0, 100
    def listdir_warm():
        return listdir_cold()

    cold, warms = run_workload("listdir", listdir_cold, listdir_warm)
    cold_t, n = cold
    warm_t = sum(w[0] for w in warms) / len(warms)
    speedup = cold_t / warm_t if warm_t > 0 else 0

    print(f"{'listdir (1000 entries)':<30} {fmt_iops(n, cold_t)+' /s':>12} "
          f"{fmt_iops(n, warm_t)+' /s':>12} {speedup:>13.1f}x")
    results["listdir"] = {
        "cold_time": cold_t, "warm_time": warm_t,
        "cache_speedup": speedup,
    }

    print()

    out_path = f"/tmp/bench_results_{label}.json"
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Results written to {out_path}")


if __name__ == "__main__":
    main()
