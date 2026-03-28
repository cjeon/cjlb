FROM ubuntu:22.04 AS builder

RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:$PATH"

WORKDIR /src
COPY . .

# Build the entire workspace in release mode
RUN cargo build --release --workspace 2>&1

# Verify the outputs exist
RUN ls -la target/release/cjlb-bootstrap target/release/cjlb-runtime target/release/e2e-helper
RUN ls -la target/release/libcjlb_shim.so || echo "WARNING: libcjlb_shim.so not found"

# --- Runtime stage ---
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    python3 \
    && rm -rf /var/lib/apt/lists/*

# Copy binaries from builder
COPY --from=builder /src/target/release/cjlb-bootstrap /test/bin/
COPY --from=builder /src/target/release/cjlb-runtime /test/bin/
COPY --from=builder /src/target/release/e2e-helper /test/bin/
COPY --from=builder /src/target/release/libcjlb_shim.so /test/bin/

# Copy test scripts
COPY e2e/run_tests.sh /test/run_tests.sh
COPY e2e/test_shim.py /test/test_shim.py
COPY e2e/benchmark.py /test/e2e/benchmark.py
COPY e2e/benchmark_data_gen.py /test/e2e/benchmark_data_gen.py
COPY e2e/cache_diag.py /test/e2e/cache_diag.py
COPY e2e/overhead_diag.py /test/e2e/overhead_diag.py

RUN chmod +x /test/run_tests.sh

WORKDIR /test
CMD ["bash", "/test/run_tests.sh"]
