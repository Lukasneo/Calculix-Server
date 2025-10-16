# ───────────────────────────────
# Stage 1: Backend (Rust)
# ───────────────────────────────
FROM rust:1.84-bookworm AS backend-builder
WORKDIR /app/backend
COPY backend ./
RUN cargo build --release --locked

# ───────────────────────────────
# Stage 2: Frontend (Node/Svelte)
# ───────────────────────────────
FROM node:20-bullseye AS frontend-builder
ARG USE_PREBUILT_FRONTEND=0
WORKDIR /app/frontend

# Install dependencies
COPY frontend/package.json frontend/package-lock.json ./
RUN if [ "$USE_PREBUILT_FRONTEND" != "1" ]; then npm ci && npm rebuild esbuild; fi

# Copy source & build
COPY frontend ./
RUN if [ "$USE_PREBUILT_FRONTEND" != "1" ]; then npm run prepare && npm run build; fi

# ───────────────────────────────
# Stage 3: Runtime (lightweight)
# ───────────────────────────────
FROM debian:bookworm-slim AS runtime
WORKDIR /app
ENV DEBIAN_FRONTEND=noninteractive

# Install CalculiX & dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends calculix-ccx ca-certificates libomp5 \
    && rm -rf /var/lib/apt/lists/*

# Copy binaries
COPY --from=backend-builder /app/backend/target/release/calculix_server /usr/local/bin/server
COPY --from=frontend-builder /app/frontend/build /app/frontend
COPY backend/benchmark.inp /app/benchmark.inp

# Environment variables
ENV APP_ADDR=0.0.0.0:8080 \
    CCX_THREADS=8 \
    FRONTEND_DIST=/app/frontend \
    DATA_ROOT=/data

# Prepare runtime directories
RUN mkdir -p /data/jobs
VOLUME ["/data"]

EXPOSE 8080
CMD ["server"]
