# ⚙️ CalculiX Server

A self-contained, Dockerized web interface for running [**CalculiX (ccx)**](https://www.calculix.de) FEM simulations — powered by a **Rust backend** and **SvelteKit frontend**.

![CalculiX Server Screenshot](./interface.jpeg)

---

## 📚 Table of Contents
- [Overview](#-overview)
- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [Prebuilt Docker Image](#-prebuilt-docker-image)
- [Configuration](#️-configuration)
- [Directory Layout](#-directory-layout)
- [Quick Start](#-quick-start)
  - [Option 1 — Docker Compose](#-option-1--using-docker-compose-recommended)
  - [Option 2 — Manual Docker Run](#-option-2--manual-docker-command)
- [Development](#-development)
- [License](#-license)
- [Acknowledgment](#-acknowledgment)

---

## 🧩 Overview

CalculiX Server lets you upload `.inp` models, run them in isolated job folders, and monitor their progress directly in the browser.  
Each job runs inside a secure Docker container with configurable thread and upload limits.  

---

## 🚀 Features

- Upload and run CalculiX `.inp` models directly from the browser.  
- Each simulation is stored in `/data/jobs/<uuid>` with all result files.  
- Give each run a **custom alias** (e.g. “Beam Test”) instead of a random hash.  
- View real-time job status, duration, solver log, and outputs.  
- Cancel or delete simulations via the web UI.  
- Download results (`.frd`, `.dat`, logs, etc.) as a ZIP archive.  
- User accounts with **email/password login**, credit balances, and admin management.  
- Admin dashboard to view, lock, or delete user accounts.  
- Everything runs in **one container** — no external web server or database needed.  

---

## 🧠 Tech Stack

| Component | Technology |
|------------|-------------|
| Backend | Rust (Axum, Tokio, tower-http) |
| Frontend | SvelteKit (static adapter) |
| Solver | CalculiX (`calculix-ccx`, Debian Bookworm) |
| Deployment | Multi-stage Docker build (Rust + Node → Debian runtime) |

---

## 💳 Credit System

- Every new user starts with **50 credits**; admins can adjust balances or grant *unlimited* credit via the admin panel.  
- When you upload an `.inp`, the server estimates runtime using a built-in benchmark and reserves the corresponding credits before the solver starts.  
- Admins and unlimited users never spend credits; their jobs still show the estimated cost for reference.  
- If CalculiX fails or the job cannot launch, the charged credits are **refunded automatically**.  
- Estimates come from a benchmark model (`backend/benchmark.inp`). Run `/api/admin/benchmark/run` to update the benchmark score after changing hardware or the file.  
- You can inspect or adjust balances through the endpoints under `/api/admin/users/{id}/credits` or via the admin UI (“Set credits” prompt accepts numbers or `unlimited`).  

---

## 🐳 Prebuilt Docker Image

A prebuilt image is available for `linux/amd64` on Docker Hub:

```bash
docker pull lukasneo/calculix-server:v1.2
```

You can optionally retag it for convenience:

```bash
docker tag lukasneo/calculix-server:v1.2 calculix-server:latest
```

---

## ⚙️ Configuration

All configuration is handled via **environment variables**:

| Variable | Default | Description |
|-----------|----------|-------------|
| `APP_ADDR` | `0.0.0.0:8080` | Bind address for the HTTP server. |
| `CCX_THREADS` | `8` | Threads passed to `ccx -nt`. |
| `UPLOAD_LIMIT_GB` | `1` | Maximum upload size (in GiB). |
| `DATA_ROOT` | `/data` | Root directory for job storage. |
| `FRONTEND_DIST` | `/app/frontend` | Internal path to built Svelte assets. |

> 💡 If `UPLOAD_LIMIT_GB` is too small or zero, the server refuses to start and prints a clear error message.

---

## 📂 Directory Layout

```
/data/
  jobs/
    <uuid>/
      model.inp
      solver.log
      *.frd
      *.dat
      other CalculiX outputs
```

Mount your host’s `./data` folder into `/data` to persist results between runs.

---

## 🧭 Quick Start

### 🪄 Option 1 — Using Docker Compose (recommended)

1. **Create a working folder**
   ```bash
   mkdir calculix-server && cd calculix-server
   ```

2. **Create a simple `docker-compose.yml`:**
   ```yaml
   services:
    calculix-server:
      image: lukasneo/calculix-server:v1.2
       ports:
         - "8080:8080"
       environment:
         - CCX_THREADS=8
         - UPLOAD_LIMIT_GB=2
       volumes:
         - ./data:/data
   ```

3. **Start it:**
   ```bash
   docker compose up -d
   ```

4. **Open the web UI:**
   ```
   http://localhost:8080
   ```

5. **Login:**  
   Default credentials →  
   **Email:** `admin@mail.com`  
   **Password:** `admin`

---

### 🧩 Option 2 — Manual Docker Command

If you don’t use Compose:

```bash
docker run --rm \
  -p 8080:8080 \
  -e CCX_THREADS=8 \
  -e UPLOAD_LIMIT_GB=2 \
  -v "$(pwd)/data:/data" \
  lukasneo/calculix-server:v1.2
```

---

## 🧱 Development

For local development (non-Docker):

| Component | Command |
|------------|----------|
| Backend | `cd backend && cargo run` |
| Frontend | `cd frontend && npm run dev` |

The Dockerfile builds both parts in release mode and packages them into a small Debian runtime image containing CalculiX.

---

## 📜 License

- **Server code:** MIT License  
- **CalculiX:** GPL License (via Debian `calculix-ccx` package)

---

## 🫶 Acknowledgment

This project builds upon the open-source [CalculiX](https://www.calculix.de) solver and the Debian `calculix-ccx` package.  
CalculiX is developed by Guido Dhondt and distributed under the GNU General Public License (GPL).
