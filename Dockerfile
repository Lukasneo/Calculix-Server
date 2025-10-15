FROM rust:1.80-bullseye AS backend-builder
WORKDIR /app/backend
COPY backend ./
RUN cargo build --release --locked

FROM node:20-bullseye AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend ./
RUN npm run prepare && npm run build

FROM debian:bookworm-slim AS runtime
WORKDIR /app

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends calculix-ccx ca-certificates libomp5 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=backend-builder /app/backend/target/release/calculix_server /usr/local/bin/server
COPY --from=frontend-builder /app/frontend/build /app/frontend

ENV APP_ADDR=0.0.0.0:8080 \
    CCX_THREADS=8 \
    FRONTEND_DIST=/app/frontend \
    DATA_ROOT=/data

RUN mkdir -p /data/jobs
VOLUME ["/data"]

EXPOSE 8080

CMD ["server"]
