# cjlb — cjeon's lockbox

A fast, Rust-powered runtime that encrypts your code and models at rest, decrypts
and caches them in memory at runtime — turning disk I/O into memory I/O while
keeping files unreadable on disk. Built for deploying to machines you don't fully trust.

## What this does

cjlb makes it **uneconomical** to steal your IP from a remote host. Files on disk
are always encrypted. At runtime, they're decrypted in memory — never written to
disk in plaintext. An attacker who grabs the filesystem gets ciphertext.

This is **not** a security guarantee against a determined attacker with root access,
hardware probes, or enough motivation. If someone really wants your bits and has
full control of the machine, they will eventually get them.

What cjlb does is raise the cost. Casual snooping, automated scraping, a curious
sysadmin browsing `/tmp` — these become fruitless. For many deployment scenarios,
that's exactly the level of protection you need.

## Example

Say you have a project you want to deploy to someone else's machine:

```
my-project/
  train.py
  model/weights.bin
  configs.json          ← tells cjlb what to run
```

`configs.json`:
```json
{
  "entrypoint": "python3 /app/train.py",
  "virtual_root": "/app"
}
```

**On your machine** — pack and deploy:

```bash
pip install cjlb

echo '{"command":"pack","input_dir":"./my-project","output_dir":"./bundle"}' > pack.json
cjlb pack.json
# Outputs: KEY:<hex>  BUNDLE_ID:<hex>  — save the key securely.

echo '{"command":"deploy","bundle_dir":"./bundle","remote_host":"user@host","remote_path":"/opt/bundle"}' > deploy.json
cjlb deploy.json
```

**From your machine** — deliver the key securely and run:

```bash
# Pipe key material over SSH — never lands on the remote filesystem or shell history.
printf '%s' "$KEY_MATERIAL" | ssh user@host 'cd /opt/bundle && ./bootstrap'
```

Nothing needs to be installed on the remote. `train.py` starts and reads files
normally under `/app/`.

### What happens under the hood

When `train.py` does `open("/app/model/weights.bin")`:

| What your code reads | What actually happens |
|---|---|
| `/app/train.py` | Intercepted by cjlb → decrypted from memory |
| `/app/model/weights.bin` | Intercepted by cjlb → decrypted from memory |
| `/etc/hosts` | Normal kernel I/O — cjlb doesn't touch it |
| `/usr/lib/libpython.so` | Normal kernel I/O — cjlb doesn't touch it |

Everything under `virtual_root` (`/app/`) is served by cjlb from the encrypted
bundle. Everything else passes through to the kernel as usual. Your code doesn't
know the difference.

**Watch out for dependencies.** If your code does `pip install` or `uv sync` at
runtime, those packages land on the real filesystem — visible to anyone on the
host. To keep dependencies protected, install them into your project directory
*before* packing so they're inside the bundle.

On disk, the bundle is AES-256-GCM ciphertext. Pages are decrypted on demand and
cached in memory — so repeated reads are fast (memory I/O, not disk I/O).
The master key travels via stdin/pipe — never touches disk, env vars, or CLI args.

## Performance

Cold = first read (nothing cached). Warm = subsequent reads (cjlb LRU cache populated).

| Workload | Encrypted cold vs plain | Encrypted warm vs plain |
|---|---|---|
| Sequential 100MB | 5x slower | **1.8x faster** |
| Random 4KB (10K ops) | 500x slower | **1.6x faster** |
| Small files (1000) | 2x slower | 2x slower |
| Dir listing (1000 entries) | 1.2x faster | 1.2x faster |

The key insight: **warm encrypted reads are faster than warm plain reads** for
large files and random access. The cjlb cache serves decrypted pages directly
from process memory — no kernel syscalls, no VFS traversal. Cold reads pay a
one-time decryption cost, then all subsequent reads benefit.

For ML workloads (large sequential reads of weights/datasets), the first load
is ~5x slower. Every load after that is faster than unencrypted.

## Requirements

| Component | Platform |
|---|---|
| `cjlb pack` / `cjlb view` | macOS (arm64), Linux (x86_64) |
| `cjlb deploy` | Anywhere with rsync |
| Runtime (LD_PRELOAD shim) | Linux x86_64 only |

The runtime uses Linux-specific syscall interception — it won't work on macOS or Windows.

## License

Free for individuals, hobbyists, startups, academics, and non-profits.
If that's you, go build something cool.

For larger commercial use, see [LICENSE](LICENSE) for details.
