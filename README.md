# [CalculiX](https://www.calculix.de) Server

Dockerized web interface for running CalculiX (ccx) FEM simulations with a Rust backend and SvelteKit frontend.

## Features
- Upload CalculiX `*.inp` models and run them inside isolated job directories (`/data/jobs/<uuid>`).
- Monitor job list with live durations, status, optional step-type detection, and solver logs.
- Cancel running jobs and delete finished/cancelled jobs (including all generated files).
- Download zipped job artefacts (logs, `.frd`, `.dat`, etc.) directly from the UI.
- Frontend served by the backend; no separate web server required.

## Tech Stack
- Backend: Rust, Axum, Tokio, tower-http.
- Frontend: SvelteKit, static adapter.
- CalculiX installed in the container (`calculix-ccx` package on Debian bookworm).
- Deployment: Docker multi-stage build + `docker compose`.

## Configuration
Environment variables (set in `docker-compose.yml` or your orchestration system):

| Variable | Default | Purpose |
| --- | --- | --- |
| `APP_ADDR` | `0.0.0.0:8080` | Bind address for the HTTP server. |
| `CCX_THREADS` | `8` | Number of threads passed to `ccx -nt`. |
| `UPLOAD_LIMIT_GB` | `1` | Maximum accepted upload size (GiB). |
| `FRONTEND_DIST` | `/app/frontend` | Location of built Svelte assets (internal). |
| `DATA_ROOT` | `/data` | Root directory for job storage (mounted volume). |

Increase `UPLOAD_LIMIT_GB` if you need to accept larger input meshes. Values ≤ `0` or that exceed the platform limit will stop the server at startup with a descriptive error.

## Directory Layout
```
/data/
  jobs/
    <uuid>/
      model.inp
      solver.log
      *.frd / *.dat / other CalculiX outputs
```

Mount the host directory `./data` into the container to persist results between runs.

## Quick Start
1. **Clone the repository**
   ```bash
   git clone https://github.com/<you>/Calculix-Server.git
   cd Calculix-Server
   ```

2. **Review environment defaults**
   - Update `CCX_THREADS` to match your CPU.
   - Adjust `UPLOAD_LIMIT_GB` if you expect large uploads.

3. **Build and run**
   ```bash
   docker compose up --build
   ```
   - The backend listens on `http://localhost:8080`.
   - Job data persists in the `./data` directory.

4. **Submit a job**
   - Open the web UI.
   - Upload a `model.inp` file.
   - Monitor progress in the job list.

5. **Cancel or delete**
   - Cancel a running job with the “Cancel” button (sends SIGKILL to `ccx` and marks the job as cancelled).
   - Delete a finished/cancelled job to remove its directory and entry from memory.

## Manual Docker Commands
If you prefer manual control without Compose:
```bash
# Build image
docker build -t calculix-server .

# Run container
docker run --rm \
  -p 8080:8080 \
  -e CCX_THREADS=8 \
  -e UPLOAD_LIMIT_GB=2 \
  -v "$(pwd)/data:/data" \
  calculix-server
```

## Offline Image Tarballs
Prebuilt images are available in the repository root:

| Architecture | File |
| --- | --- |
| `linux/amd64` | `calculix-server-amd64.tar` |
| `linux/arm64` | `calculix-server-arm64.tar` |

Load the variant that matches your target host:

```bash
# AMD64 / x86_64 host
docker load < calculix-server-amd64.tar

# ARM64 / Apple Silicon / Graviton host
docker load < calculix-server-arm64.tar
```

After loading, the image is tagged as `calculix-server:amd64` or `calculix-server:arm64`. You can re-tag if desired, e.g. `docker tag calculix-server:amd64 calculix-server:latest`.

## Development Notes
- Backend lives in `backend/` (`cargo run` for local debugging).
- Frontend lives in `frontend/` (`npm run dev` for local preview).
- The Docker build stages handle release builds for both parts and copy their artefacts into a slim Debian image with CalculiX preinstalled.

## License
MIT for the server components. CalculiX itself is distributed under the GPL; see `calculix-ccx` package for full terms.
