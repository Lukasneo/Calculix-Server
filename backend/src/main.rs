use std::{
    collections::HashMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Instant,
};

use anyhow::{Context, Result};
use axum::extract::multipart::Field;
use axum::{
    body::Bytes,
    extract::{Multipart, Path as AxumPath, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::{fs, io::AsyncWriteExt, net::TcpListener, process::Command, sync::RwLock};
use tower_http::services::{ServeDir, ServeFile};
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use uuid::Uuid;
use zip::write::FileOptions;

#[derive(Clone)]
struct AppState {
    jobs: Arc<RwLock<HashMap<Uuid, JobEntry>>>,
    jobs_dir: Arc<PathBuf>,
    ccx_threads: usize,
}

#[derive(Clone)]
struct JobEntry {
    id: Uuid,
    running: bool,
    done: bool,
    started_at: DateTime<Utc>,
    started_instant: Instant,
    duration: Option<f64>,
    job_type: Option<String>,
    log_path: PathBuf,
    job_dir: PathBuf,
    error: Option<String>,
}

#[derive(Serialize)]
struct JobSummary {
    id: Uuid,
    running: bool,
    done: bool,
    start_time: DateTime<Utc>,
    duration_seconds: f64,
    job_type: Option<String>,
    error: Option<String>,
}

#[derive(Serialize)]
struct UploadResponse {
    id: Uuid,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Debug)]
struct AppError {
    status: StatusCode,
    message: String,
}

impl AppError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }

    fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let payload = Json(ErrorResponse {
            error: self.message,
        });
        (self.status, payload).into_response()
    }
}

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        AppError::internal(err.to_string())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env()
                .or_else(|_| EnvFilter::try_new("info"))
                .unwrap(),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let data_root =
        PathBuf::from(std::env::var("DATA_ROOT").unwrap_or_else(|_| "/data".to_string()));
    let jobs_dir = data_root.join("jobs");
    fs::create_dir_all(&jobs_dir)
        .await
        .context("Failed to ensure /data/jobs directory exists")?;

    let ccx_threads = std::env::var("CCX_THREADS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|threads| *threads > 0)
        .unwrap_or(8);

    let frontend_dir =
        PathBuf::from(std::env::var("FRONTEND_DIST").unwrap_or_else(|_| "frontend/build".into()));

    let state = AppState {
        jobs: Arc::new(RwLock::new(HashMap::new())),
        jobs_dir: Arc::new(jobs_dir.clone()),
        ccx_threads,
    };

    let upload_router = Router::new()
        .route("/upload", post(upload))
        .route("/status", get(status))
        .route("/download/:id", get(download));

    let static_service = ServeDir::new(frontend_dir.clone())
        .not_found_service(ServeFile::new(frontend_dir.join("index.html")));

    let app = upload_router
        .fallback_service(static_service)
        .with_state(state.clone());

    let addr: SocketAddr = std::env::var("APP_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
        .parse()
        .context("Invalid APP_ADDR value")?;

    info!("Starting server on {addr}");
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}

async fn upload(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<Json<UploadResponse>, AppError> {
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|err| AppError::internal(err.to_string()))?
    {
        let field = field;
        let file_name = field
            .file_name()
            .map(|name| name.to_string())
            .ok_or_else(|| AppError::bad_request("Uploaded file must include a filename"))?;

        if !file_name.to_lowercase().ends_with(".inp") {
            return Err(AppError::bad_request("Only .inp files are accepted"));
        }

        return process_inp_upload(field, state).await;
    }

    Err(AppError::bad_request(
        "No valid .inp file found in upload request",
    ))
}

async fn process_inp_upload(
    mut field: Field<'_>,
    state: AppState,
) -> Result<Json<UploadResponse>, AppError> {
    let job_id = Uuid::new_v4();
    let job_dir = state.jobs_dir.join(job_id.to_string());
    fs::create_dir_all(&job_dir)
        .await
        .map_err(|err| AppError::internal(format!("Failed to create job directory: {err}")))?;

    let model_path = job_dir.join("model.inp");
    let mut file = fs::File::create(&model_path)
        .await
        .map_err(|err| AppError::internal(format!("Failed to create model.inp: {err}")))?;

    while let Some(chunk) = field
        .chunk()
        .await
        .map_err(|err| AppError::internal(format!("Failed to read upload chunk: {err}")))?
    {
        file.write_all(&chunk)
            .await
            .map_err(|err| AppError::internal(format!("Failed writing model.inp: {err}")))?;
    }

    file.flush()
        .await
        .map_err(|err| AppError::internal(format!("Failed to flush model.inp: {err}")))?;

    let detected_job_type = detect_job_type(&model_path).await.unwrap_or(None);

    let job_entry = JobEntry {
        id: job_id,
        running: true,
        done: false,
        started_at: Utc::now(),
        started_instant: Instant::now(),
        duration: None,
        job_type: detected_job_type,
        log_path: job_dir.join("solver.log"),
        job_dir: job_dir.clone(),
        error: None,
    };

    {
        let mut jobs = state.jobs.write().await;
        jobs.insert(job_id, job_entry.clone());
    }

    tokio::spawn(run_calculix_job(state, job_id));

    Ok(Json(UploadResponse { id: job_id }))
}

async fn detect_job_type(path: &Path) -> Result<Option<String>> {
    let data = fs::read_to_string(path).await?;
    let upper = data.to_uppercase();
    let patterns = [
        ("*STATIC", "STATIC"),
        ("*FREQUENCY", "FREQUENCY"),
        ("*BUCKLE", "BUCKLE"),
        ("*HEAT", "HEAT"),
    ];

    for (pattern, label) in patterns {
        if upper.contains(pattern) {
            return Ok(Some(label.to_string()));
        }
    }

    Ok(None)
}

async fn run_calculix_job(state: AppState, job_id: Uuid) {
    let (job_dir, log_path, threads) = {
        let jobs = state.jobs.read().await;
        match jobs.get(&job_id) {
            Some(entry) => (
                entry.job_dir.clone(),
                entry.log_path.clone(),
                state.ccx_threads,
            ),
            None => {
                error!("Job {job_id} not found in registry");
                return;
            }
        }
    };

    // Run CalculiX and capture stdout/stderr into solver.log
    let result = async {
        let log_file = std::fs::File::create(&log_path)?;
        let log_file_err = log_file.try_clone()?;

        let mut command = Command::new("ccx");
        command
            .arg("-i")
            .arg("model")
            .arg("-nt")
            .arg(threads.to_string())
            .current_dir(&job_dir)
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(log_file_err));

        info!("Starting CalculiX job {job_id}");
        let status = command.status().await?;

        let mut jobs = state.jobs.write().await;
        if let Some(entry) = jobs.get_mut(&job_id) {
            entry.running = false;
            entry.done = true;
            entry.duration = Some(entry.started_instant.elapsed().as_secs_f64());
            if !status.success() {
                entry.error = Some(format!("CalculiX exited with status: {}", status));
                error!("CalculiX job {job_id} failed: {status}");
            } else {
                info!("CalculiX job {job_id} completed successfully");
            }
        }
        Result::<()>::Ok(())
    }
    .await;

    if let Err(err) = result {
        error!("CalculiX job {job_id} failed to run: {err:?}");
        let mut jobs = state.jobs.write().await;
        if let Some(entry) = jobs.get_mut(&job_id) {
            entry.running = false;
            entry.done = true;
            entry.duration = Some(entry.started_instant.elapsed().as_secs_f64());
            entry.error = Some(err.to_string());
        }
    }
}

async fn status(State(state): State<AppState>) -> Result<Json<Vec<JobSummary>>, AppError> {
    let jobs = state.jobs.read().await;
    let mut summaries: Vec<JobSummary> = jobs
        .values()
        .map(|entry| {
            let duration = if entry.running {
                entry.started_instant.elapsed().as_secs_f64()
            } else {
                entry.duration.unwrap_or_default()
            };

            JobSummary {
                id: entry.id,
                running: entry.running,
                done: entry.done,
                start_time: entry.started_at,
                duration_seconds: duration,
                job_type: entry.job_type.clone(),
                error: entry.error.clone(),
            }
        })
        .collect();

    summaries.sort_by_key(|summary| summary.start_time);
    summaries.reverse();

    Ok(Json(summaries))
}

async fn download(
    AxumPath(job_id): AxumPath<Uuid>,
    State(state): State<AppState>,
) -> Result<Response, AppError> {
    let job = {
        let jobs = state.jobs.read().await;
        jobs.get(&job_id).cloned()
    };

    let job = job.ok_or_else(|| AppError::not_found("Job not found"))?;

    let zip_bytes = tokio::task::spawn_blocking(move || create_results_archive(&job.job_dir))
        .await
        .map_err(|err| AppError::internal(format!("Failed to join archive task: {err}")))?
        .map_err(|err| AppError::internal(format!("Failed to create archive: {err}")))?;

    let filename = format!("{job_id}.zip");
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "application/zip".parse().unwrap());
    headers.insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{filename}\"")
            .parse()
            .unwrap(),
    );

    let body = Bytes::from(zip_bytes);

    Ok((headers, body).into_response())
}

fn create_results_archive(job_dir: &Path) -> Result<Vec<u8>> {
    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut cursor);
        let options = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for entry in std::fs::read_dir(job_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                let file_name = entry.file_name().to_string_lossy().to_string();
                writer.start_file(file_name, options)?;
                let mut file = std::fs::File::open(&path)?;
                std::io::copy(&mut file, &mut writer)?;
            }
        }
        writer.finish()?;
    }

    Ok(cursor.into_inner())
}
