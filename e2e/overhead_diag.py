#!/usr/bin/env python3
"""Detailed cold-vs-cold overhead breakdown.

Measures each component of an encrypted cold random read and compares
with an unencrypted cold random read. All numbers averaged over multiple runs.

Usage:
  Plain mode:     python3 overhead_diag.py <bundle_dir> plain
  Encrypted mode: python3 overhead_diag.py <virtual_root> encrypted
"""
import os
import random
import sys
import time

RUNS = 5        # average over this many runs
N = 500         # ops per run (kept modest so total time is reasonable)
PAGE = 1_048_576
BLOCK = 4096


def flush_caches():
    try:
        open("/proc/sys/vm/drop_caches", "w").write("3\n")
    except:
        pass


def avg(vals):
    return sum(vals) / len(vals)


def report(label, times_us):
    a = avg(times_us)
    lo = min(times_us)
    hi = max(times_us)
    print(f"  {label:<40} {a:8.1f} us   (min={lo:.1f}, max={hi:.1f})")
    return a


def run_plain(base):
    """Measure every component of the unencrypted + encrypted cold read path."""

    # Find the chunk file (for I/O tests on realistic data)
    chunk_dir = os.path.join(base, "chunks")
    chunk_files = sorted(os.listdir(chunk_dir)) if os.path.isdir(chunk_dir) else []
    chunk = os.path.join(chunk_dir, chunk_files[0]) if chunk_files else None

    large = os.path.join(base, "large", "100mb.bin")
    target = chunk if chunk else large
    file_size = os.path.getsize(target)

    rng = random.Random(42)

    print(f"=== COLD READ OVERHEAD BREAKDOWN (averaged over {RUNS} runs x {N} ops) ===")
    print(f"    target: {os.path.basename(target)} ({file_size:,} bytes)")
    print()

    # ── A. Unencrypted baseline: random 4KB read ────────────────────
    print("── Unencrypted random 4KB read ──")
    vals = []
    for _ in range(RUNS):
        offsets = [rng.randint(0, file_size - BLOCK) for _ in range(N)]
        flush_caches()
        t0 = time.perf_counter()
        fd = os.open(target, os.O_RDONLY)
        for off in offsets:
            os.lseek(fd, off, os.SEEK_SET)
            os.read(fd, BLOCK)
        os.close(fd)
        vals.append((time.perf_counter() - t0) / N * 1e6)
    t_plain_4k = report("seek+read(4KB) on open fd", vals)

    # ── B. Component: file open + close ─────────────────────────────
    print()
    print("── Encrypted read components (measured individually) ──")

    vals = []
    for _ in range(RUNS):
        t0 = time.perf_counter()
        for _ in range(N):
            fd = os.open(target, os.O_RDONLY)
            os.close(fd)
        vals.append((time.perf_counter() - t0) / N * 1e6)
    t_open_close = report("(a) open + close (no I/O)", vals)

    # ── C. Component: seek + read 1MB on open fd ────────────────────
    vals = []
    for _ in range(RUNS):
        offsets = [rng.randint(0, max(1, file_size - PAGE)) for _ in range(N)]
        fd = os.open(target, os.O_RDONLY)
        t0 = time.perf_counter()
        for off in offsets:
            os.lseek(fd, off, os.SEEK_SET)
            os.read(fd, PAGE)
        elapsed = (time.perf_counter() - t0) / N * 1e6
        os.close(fd)
        vals.append(elapsed)
    t_seek_read_1mb = report("(b) seek+read(1MB) on open fd", vals)

    # ── D. Component: open + seek + read 1MB + close ────────────────
    vals = []
    for _ in range(RUNS):
        offsets = [rng.randint(0, max(1, file_size - PAGE)) for _ in range(N)]
        t0 = time.perf_counter()
        for off in offsets:
            fd = os.open(target, os.O_RDONLY)
            os.lseek(fd, off, os.SEEK_SET)
            os.read(fd, PAGE)
            os.close(fd)
        vals.append((time.perf_counter() - t0) / N * 1e6)
    t_open_read_1mb_close = report("(c) open+seek+read(1MB)+close", vals)

    # ── E. Component: 1MB heap allocation ───────────────────────────
    vals = []
    for _ in range(RUNS):
        t0 = time.perf_counter()
        for _ in range(N):
            buf = bytearray(PAGE)
            del buf
        vals.append((time.perf_counter() - t0) / N * 1e6)
    t_alloc_1mb = report("(d) alloc+free 1MB (Python)", vals)

    # ── F. Component: memcpy 4KB (simulate copy to user buf) ────────
    src = bytearray(PAGE)
    vals = []
    for _ in range(RUNS):
        t0 = time.perf_counter()
        for _ in range(N):
            _ = bytes(src[:BLOCK])
        vals.append((time.perf_counter() - t0) / N * 1e6)
    t_memcpy = report("(e) memcpy 4KB from 1MB buffer", vals)

    # ── Summary ─────────────────────────────────────────────────────
    print()
    print("── Summary ──")
    print(f"  {'Unencrypted random 4KB (baseline):':<40} {t_plain_4k:8.1f} us")
    print()
    print(f"  Encrypted random 4KB estimated breakdown:")
    print(f"    {'(c) I/O: open+seek+read(1MB)+close':<40} {t_open_read_1mb_close:8.1f} us")
    t_aes = "???"
    print(f"    {'    AES-256-GCM decrypt 1MB':<40} {t_aes:>8} us  ← from Rust-side")
    print(f"    {'(d) alloc+free 1MB (x2 for buf+decrypt)':<40} {t_alloc_1mb*2:8.1f} us")
    print(f"    {'(e) memcpy 4KB to user buffer':<40} {t_memcpy:8.1f} us")
    print(f"    {'    route table span walk + cache ops':<40} {'~few':>8} us")
    accounted = t_open_read_1mb_close + t_alloc_1mb * 2 + t_memcpy
    print(f"    {'─── accounted (excl. AES)':<40} {accounted:8.1f} us")
    print()
    read_amp = PAGE / BLOCK
    print(f"  Read amplification: {read_amp:.0f}x (read {PAGE/1024:.0f}KB to serve {BLOCK/1024:.0f}KB)")
    expected = t_plain_4k * read_amp
    print(f"  Theoretical minimum overhead: {t_plain_4k:.1f} x {read_amp:.0f} = {expected:.1f} us")

    return {
        "plain_4k": t_plain_4k,
        "open_close": t_open_close,
        "seek_read_1mb": t_seek_read_1mb,
        "open_read_1mb_close": t_open_read_1mb_close,
        "alloc_1mb": t_alloc_1mb,
        "memcpy_4k": t_memcpy,
    }


def run_encrypted(base):
    """Measure the actual encrypted cold random read via shim."""
    large = os.path.join(base, "large", "100mb.bin")
    file_size = 100 * 1024 * 1024
    rng = random.Random(42)

    print(f"=== ENCRYPTED COLD RANDOM 4KB (averaged over {RUNS} runs x {N} ops, no cache) ===")
    print()

    vals = []
    for r in range(RUNS):
        offsets = [rng.randint(0, file_size - BLOCK) for _ in range(N)]
        t0 = time.perf_counter()
        with open(large, "rb") as f:
            for off in offsets:
                f.seek(off)
                f.read(BLOCK)
        vals.append((time.perf_counter() - t0) / N * 1e6)
    t_enc = report("encrypted random 4KB (total)", vals)

    return {"encrypted_4k": t_enc}


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <dir> <plain|encrypted>", file=sys.stderr)
        sys.exit(1)

    base = sys.argv[1]
    mode = sys.argv[2]

    if mode == "plain":
        run_plain(base)
    elif mode == "encrypted":
        run_encrypted(base)


if __name__ == "__main__":
    main()
