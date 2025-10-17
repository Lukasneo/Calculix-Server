use std::{
    collections::HashMap,
    env,
    io::ErrorKind,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Instant,
};

use anyhow::{anyhow, bail, Context, Result};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::extract::multipart::Field;
use axum::extract::DefaultBodyLimit;
use axum::{
    async_trait,
    body::{Body, Bytes},
    extract::{FromRef, FromRequestParts, Multipart, Path as AxumPath, State},
    http::{header, request::Parts, HeaderMap, Request, StatusCode},
    middleware::{from_fn_with_state, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post},
    Json, Router,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use chrono::{DateTime, Duration, TimeZone, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use lettre::{
    message::{header::ContentType, Mailbox, Message},
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Tokio1Executor,
};
use password_hash::SaltString;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use sqlx::{
    query, query_as,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    FromRow, SqlitePool,
};
use std::str::FromStr;
use tera::{Context as TeraContext, Tera};
use time::OffsetDateTime;
use tokio::{
    fs, fs::OpenOptions, io::AsyncWriteExt, net::TcpListener, process::Command, sync::RwLock,
};
use tokio_util::sync::CancellationToken;
use tower_http::services::{ServeDir, ServeFile};
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use uuid::Uuid;
use zip::write::FileOptions;

#[derive(Clone)]
struct AppState {
    jobs: Arc<RwLock<HashMap<Uuid, JobEntry>>>,
    jobs_dir: Arc<PathBuf>,
    ccx_threads: usize,
    db_pool: SqlitePool,
    jwt_encoding_key: Arc<EncodingKey>,
    jwt_decoding_key: Arc<DecodingKey>,
    jwt_ttl_seconds: i64,
    smtp_config_path: Arc<PathBuf>,
    smtp_config: Arc<RwLock<Option<SmtpConfig>>>,
    email_templates: EmailTemplateEngine,
    mail_log_path: Arc<PathBuf>,
    mail_base_url: Arc<RwLock<Option<String>>>,
    max_upload_bytes: usize,
}

#[derive(Clone)]
struct JobEntry {
    id: Uuid,
    owner_id: i64,
    alias: String,
    running: bool,
    done: bool,
    cancelled: bool,
    started_at: DateTime<Utc>,
    started_instant: Instant,
    duration: Option<f64>,
    job_type: Option<String>,
    log_path: PathBuf,
    job_dir: PathBuf,
    error: Option<String>,
    cancel_token: Option<CancellationToken>,
    element_count: usize,
    estimated_runtime_seconds: f64,
    benchmark_score: f64,
    estimated_credits: f64,
    charged_credits: f64,
}

#[derive(Serialize)]
struct JobSummary {
    id: Uuid,
    owner_id: i64,
    alias: String,
    running: bool,
    done: bool,
    cancelled: bool,
    start_time: DateTime<Utc>,
    duration_seconds: f64,
    job_type: Option<String>,
    error: Option<String>,
    element_count: usize,
    estimated_runtime_seconds: f64,
    benchmark_score: f64,
    estimated_credits: f64,
    charged_credits: f64,
}

#[derive(Serialize)]
struct UploadResponse {
    id: Uuid,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SmtpConfig {
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    from_address: String,
    use_tls: bool,
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 587,
            username: None,
            password: None,
            from_address: String::new(),
            use_tls: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct SmtpConfigInput {
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    from_address: String,
    use_tls: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum MailStatus {
    Sent,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MailLogEntry {
    timestamp: String,
    to: String,
    subject: String,
    template: String,
    status: MailStatus,
    error: Option<String>,
}

fn normalize_optional_field(value: Option<String>) -> Option<String> {
    value.and_then(|raw| {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn parse_mailbox_address(address: &str, field: &str) -> Result<Mailbox, AppError> {
    address
        .parse::<Mailbox>()
        .map_err(|err| AppError::bad_request(format!("Invalid {field}: {err}")))
}

fn normalize_smtp_config(input: SmtpConfigInput) -> Result<SmtpConfig, AppError> {
    let host = input.host.trim().to_string();
    if host.is_empty() {
        return Err(AppError::bad_request("SMTP host is required"));
    }

    if input.port == 0 {
        return Err(AppError::bad_request(
            "SMTP port must be between 1 and 65535",
        ));
    }

    let from_address = input.from_address.trim().to_string();
    if from_address.is_empty() {
        return Err(AppError::bad_request("SMTP from address is required"));
    }
    parse_mailbox_address(&from_address, "from address")?;

    if let Some(username) = &input.username {
        if username.trim().is_empty() {
            return Err(AppError::bad_request("SMTP username cannot be empty"));
        }
    }

    let username = normalize_optional_field(input.username);
    let password = normalize_optional_field(input.password);

    Ok(SmtpConfig {
        host,
        port: input.port,
        username,
        password,
        from_address,
        use_tls: input.use_tls,
    })
}

#[derive(Clone)]
struct EmailTemplateEngine {
    tera: Arc<Tera>,
}

impl EmailTemplateEngine {
    fn new(base_dir: &Path) -> Result<Self, AppError> {
        let resolved = base_dir.canonicalize().map_err(|err| {
            AppError::internal(format!(
                "Failed to resolve email template directory ({}): {err}",
                base_dir.display()
            ))
        })?;
        let pattern = format!("{}/**/*", resolved.display());
        let mut tera = Tera::new(&pattern)
            .map_err(|err| AppError::internal(format!("Failed to load email templates: {err}")))?;
        tera.autoescape_on(vec![".html", ".htm"]);
        Ok(Self {
            tera: Arc::new(tera),
        })
    }

    fn render<T: Serialize>(&self, template: &str, data: &T) -> Result<String, AppError> {
        let context = TeraContext::from_serialize(data).map_err(|err| {
            AppError::internal(format!("Failed to serialise email template context: {err}"))
        })?;

        self.tera.render(template, &context).map_err(|err| {
            AppError::internal(format!("Failed to render template {template}: {err}"))
        })
    }
}

#[derive(Clone)]
struct JobCompletionEmail {
    job_id: Uuid,
    owner_id: i64,
    alias: String,
    start_time: DateTime<Utc>,
    end_time: DateTime<Utc>,
    duration_seconds: f64,
    credits_used: f64,
}

fn format_duration_hms(duration_seconds: f64) -> String {
    let total_seconds = if duration_seconds.is_finite() && duration_seconds > 0.0 {
        duration_seconds.floor() as u64
    } else {
        0
    };

    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;

    format!("{hours:02}:{minutes:02}:{seconds:02}")
}

fn normalize_mail_base_url(input: &str) -> Result<Option<String>, AppError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    let value = trimmed.trim_end_matches('/').trim().to_string();
    if !(value.starts_with("http://") || value.starts_with("https://")) {
        return Err(AppError::bad_request(
            "Mail base URL must start with http:// or https://",
        ));
    }

    Ok(Some(value))
}

fn compose_mail_link(base: Option<&String>, fallback_path: &str) -> String {
    match base {
        Some(base_url) if !base_url.is_empty() => base_url.clone(),
        _ => {
            if fallback_path.starts_with('/') {
                fallback_path.to_string()
            } else {
                format!("/{}", fallback_path)
            }
        }
    }
}

async fn load_smtp_config_from_disk(path: &Path) -> Result<Option<SmtpConfig>, AppError> {
    match fs::read(path).await {
        Ok(bytes) => {
            if bytes.is_empty() {
                return Ok(None);
            }
            let raw: SmtpConfigInput = serde_json::from_slice(&bytes).map_err(|err| {
                AppError::internal(format!("Failed to parse SMTP config file: {err}"))
            })?;
            let config = match normalize_smtp_config(raw) {
                Ok(value) => value,
                Err(err) => {
                    return Err(AppError::internal(format!(
                        "Stored SMTP config is invalid: {}",
                        err.message
                    )))
                }
            };
            Ok(Some(config))
        }
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => Err(AppError::internal(format!(
            "Failed to read SMTP config file: {err}"
        ))),
    }
}

async fn persist_smtp_config(path: &Path, config: &SmtpConfig) -> Result<(), AppError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await.map_err(|err| {
            AppError::internal(format!("Failed to prepare SMTP config path: {err}"))
        })?;
    }

    let mut payload = serde_json::to_vec_pretty(config)
        .map_err(|err| AppError::internal(format!("Failed to serialise SMTP config: {err}")))?;
    payload.push(b'\n');

    fs::write(path, payload)
        .await
        .map_err(|err| AppError::internal(format!("Failed to write SMTP config: {err}")))?;

    Ok(())
}

fn build_smtp_transport(
    config: &SmtpConfig,
) -> Result<AsyncSmtpTransport<Tokio1Executor>, AppError> {
    let host = config.host.trim();
    let mut builder = if config.use_tls {
        AsyncSmtpTransport::<Tokio1Executor>::relay(host)
            .map_err(|err| AppError::bad_request(format!("Failed to configure SMTP relay: {err}")))?
            .port(config.port)
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host).port(config.port)
    };

    if let Some(username) = &config.username {
        let password = config.password.clone().unwrap_or_default();
        builder = builder.credentials(Credentials::new(username.clone(), password));
    }

    Ok(builder.build())
}

async fn append_mail_log(path: &Path, entry: &MailLogEntry) -> Result<(), AppError> {
    let mut payload = serde_json::to_vec(entry)
        .map_err(|err| AppError::internal(format!("Failed to serialise mail log entry: {err}")))?;
    payload.push(b'\n');

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
        .map_err(|err| AppError::internal(format!("Failed to open mail log: {err}")))?;

    file.write_all(&payload)
        .await
        .map_err(|err| AppError::internal(format!("Failed to write mail log: {err}")))?;

    Ok(())
}

async fn send_templated_email(
    state: &AppState,
    recipient: &str,
    subject: &str,
    template: &str,
    variables: JsonValue,
) -> Result<(), AppError> {
    let timestamp = Utc::now().to_rfc3339();
    let mut log_entry = MailLogEntry {
        timestamp,
        to: recipient.to_string(),
        subject: subject.to_string(),
        template: template.to_string(),
        status: MailStatus::Sent,
        error: None,
    };

    let result: Result<(), AppError> = async {
        let config = {
            let guard = state.smtp_config.read().await;
            guard.clone()
        }
        .ok_or_else(|| AppError::bad_request("Configure SMTP settings before sending mail"))?;

        let body = state.email_templates.render(template, &variables)?;

        let transport = build_smtp_transport(&config)?;

        let from_mailbox = parse_mailbox_address(&config.from_address, "from address")?;
        let to_mailbox = parse_mailbox_address(recipient, "recipient")?;

        let message = Message::builder()
            .from(from_mailbox)
            .to(to_mailbox)
            .subject(subject)
            .header(ContentType::TEXT_HTML)
            .body(body)
            .map_err(|err| AppError::internal(format!("Failed to build email: {err}")))?;

        transport
            .send(message)
            .await
            .map_err(|err| AppError::internal(format!("Failed to send email: {err}")))?;

        Ok(())
    }
    .await;

    if let Err(err) = &result {
        log_entry.status = MailStatus::Failed;
        log_entry.error = Some(err.message.clone());
    }

    if let Err(log_err) = append_mail_log(state.mail_log_path.as_ref(), &log_entry).await {
        warn!("Failed to append mail log entry: {}", log_err.message);
    }

    result
}

async fn send_smtp_test_email(state: &AppState, recipient: &str) -> Result<(), AppError> {
    let now = Utc::now();
    let base = state.mail_base_url.read().await.clone();
    let link = compose_mail_link(base.as_ref(), "/");

    let payload = json!({
        "alias": "Test Simulation",
        "start_time": now.to_rfc3339(),
        "end_time": now.to_rfc3339(),
        "duration": "0s",
        "credits_used": 0,
        "link": link
    });

    send_templated_email(
        state,
        recipient,
        "Calculix Server SMTP Test",
        "test_email.html",
        payload,
    )
    .await
}

async fn notify_job_completion(
    state: &AppState,
    payload: JobCompletionEmail,
) -> Result<(), AppError> {
    let user = fetch_user_by_id(&state.db_pool, payload.owner_id).await?;
    let duration = format_duration_hms(payload.duration_seconds);
    let base = state.mail_base_url.read().await.clone();
    let link = compose_mail_link(base.as_ref(), &format!("/jobs/{}", payload.job_id));

    let context = json!({
        "alias": payload.alias,
        "start_time": payload.start_time.to_rfc3339(),
        "end_time": payload.end_time.to_rfc3339(),
        "duration": duration,
        "credits_used": format!("{:.3}", payload.credits_used),
        "link": link,
    });

    let subject = format!("Simulation \"{}\" finished", payload.alias);
    send_templated_email(
        state,
        &user.email,
        &subject,
        "simulation_finished.html",
        context,
    )
    .await
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

    fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, message)
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, message)
    }

    fn payment_required(message: impl Into<String>) -> Self {
        Self::new(StatusCode::PAYMENT_REQUIRED, message)
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

const ROLE_USER: &str = "user";
const ROLE_ADMIN: &str = "admin";
const AUTH_COOKIE: &str = "auth_token";
const PASSWORD_MIN_LEN: usize = 8;
const MAX_ALIAS_LENGTH: usize = 100;
const DEFAULT_SIM_STATUS: &str = "pending";
const SETTING_ALLOW_SIGNUPS: &str = "allow_signups";
const SETTING_BENCHMARK_SCORE: &str = "benchmark_score";
const SETTING_BENCHMARK_RECORDED_AT: &str = "benchmark_recorded_at";
const SETTING_MAIL_BASE_URL: &str = "mail_base_url";
const BENCHMARK_INPUT_PATH: &str = "/app/benchmark.inp";
const EMAIL_TEMPLATE_DIR: &str = "/app/templates/email";
const CREDIT_REFERENCE_SCORE: f64 = 0.01;
const CREDIT_SECONDS_PER_ELEMENT: f64 = 0.02;
const CREDIT_MIN_ESTIMATED_RUNTIME: f64 = 5.0;
const DEFAULT_USER_CREDITS: f64 = 50.0;
const CREDIT_BALANCE_EPSILON: f64 = 1e-6;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum UserRole {
    User,
    Admin,
}

impl UserRole {
    fn as_str(&self) -> &'static str {
        match self {
            UserRole::User => ROLE_USER,
            UserRole::Admin => ROLE_ADMIN,
        }
    }

    fn from_db(value: &str) -> Result<Self, AppError> {
        match value {
            ROLE_USER => Ok(UserRole::User),
            ROLE_ADMIN => Ok(UserRole::Admin),
            other => Err(AppError::internal(format!("Unknown user role: {other}"))),
        }
    }

    fn is_admin(&self) -> bool {
        matches!(self, UserRole::Admin)
    }
}

#[derive(Debug, Clone, FromRow)]
struct UserRecord {
    id: i64,
    email: String,
    password_hash: String,
    role: String,
    active: bool,
    credits: f64,
    unlimited: bool,
    created_at: i64,
}

#[derive(Serialize)]
struct UserResponse {
    id: i64,
    email: String,
    role: UserRole,
    active: bool,
    credits: f64,
    unlimited: bool,
    created_at: String,
}

#[derive(Serialize)]
struct AuthUserSummary {
    id: i64,
    email: String,
}

#[derive(Serialize)]
struct AuthLoginResponse {
    access_token: String,
    user: AuthUserSummary,
}

#[derive(Serialize)]
struct ProfileResponse {
    id: i64,
    email: String,
    role: UserRole,
    active: bool,
    credits: f64,
    unlimited: bool,
}

#[derive(Serialize)]
struct AdminUserResponse {
    id: i64,
    email: String,
    role: UserRole,
    active: bool,
    credits: f64,
    unlimited: bool,
    created_at: String,
}

#[derive(Serialize)]
struct SettingsResponse {
    allow_signups: bool,
    mail_base_url: Option<String>,
}

#[derive(Serialize)]
struct BenchmarkResponse {
    score_seconds: Option<f64>,
    recorded_at: Option<String>,
}

struct JobCreditEstimate {
    estimated_credits: f64,
    estimated_runtime_seconds: f64,
    element_count: usize,
    benchmark_score: f64,
}

struct CreditEstimator {
    reference_score: f64,
    seconds_per_element: f64,
    min_runtime_seconds: f64,
}

impl CreditEstimator {
    fn new(reference_score: f64, seconds_per_element: f64, min_runtime_seconds: f64) -> Self {
        Self {
            reference_score,
            seconds_per_element,
            min_runtime_seconds,
        }
    }

    fn calculate(&self, estimated_runtime_seconds: f64, benchmark_score: f64) -> f64 {
        let benchmark = if benchmark_score > 0.0 {
            benchmark_score
        } else {
            self.reference_score
        };

        (estimated_runtime_seconds * self.reference_score) / benchmark
    }

    fn estimate_runtime_from_elements(&self, element_count: usize) -> f64 {
        let computed = element_count as f64 * self.seconds_per_element;
        let sanitized = if computed.is_finite() { computed } else { 0.0 };
        sanitized.max(self.min_runtime_seconds)
    }

    async fn estimate_from_contents(
        &self,
        pool: &SqlitePool,
        contents: &str,
    ) -> Result<JobCreditEstimate, AppError> {
        let mut element_count = count_elements_in_inp(contents);
        if element_count == 0 {
            element_count = count_nodes_in_inp(contents);
        }

        let benchmark_score = load_benchmark_score(pool, self.reference_score).await?;
        let estimated_runtime_seconds = self.estimate_runtime_from_elements(element_count);
        let estimated_credits = self.calculate(estimated_runtime_seconds, benchmark_score);

        Ok(JobCreditEstimate {
            estimated_credits,
            estimated_runtime_seconds,
            element_count,
            benchmark_score,
        })
    }

    async fn estimate_from_input_file(
        &self,
        pool: &SqlitePool,
        path: &Path,
    ) -> Result<JobCreditEstimate, AppError> {
        let contents = fs::read_to_string(path)
            .await
            .map_err(|err| AppError::internal(format!("Failed to read job input file: {err}")))?;

        self.estimate_from_contents(pool, &contents).await
    }

    async fn estimate_job_cost(
        &self,
        state: &AppState,
        job_id: Uuid,
    ) -> Result<JobCreditEstimate, AppError> {
        let job = {
            let jobs = state.jobs.read().await;
            jobs.get(&job_id).cloned()
        }
        .ok_or_else(|| AppError::not_found("Job not found"))?;

        let model_path = job.job_dir.join("model.inp");
        self.estimate_from_input_file(&state.db_pool, &model_path)
            .await
    }
}

impl Default for CreditEstimator {
    fn default() -> Self {
        CreditEstimator::new(
            CREDIT_REFERENCE_SCORE,
            CREDIT_SECONDS_PER_ELEMENT,
            CREDIT_MIN_ESTIMATED_RUNTIME,
        )
    }
}
#[derive(Serialize)]
struct JobEstimateResponse {
    job_id: Uuid,
    estimated_credits: f64,
    estimated_runtime_seconds: f64,
    element_count: usize,
    benchmark_score: f64,
    charged_credits: f64,
}

#[derive(Serialize)]
struct UserCreditsResponse {
    id: i64,
    email: String,
    credits: f64,
    unlimited: bool,
}

#[derive(Serialize)]
struct JobEstimatePreviewResponse {
    estimated_credits: f64,
    estimated_runtime_seconds: f64,
    element_count: usize,
    benchmark_score: f64,
    charged_credits: f64,
}

#[derive(Serialize)]
struct SimulationSendResponse {
    alias: String,
    estimated_credits: f64,
    estimated_time_s: f64,
}

#[derive(Serialize)]
struct SimulationStartResponse {
    status: String,
    alias: String,
}

#[derive(Deserialize)]
struct UpdateSettingsPayload {
    allow_signups: Option<bool>,
    mail_base_url: Option<String>,
}

#[derive(Deserialize)]
struct AdjustCreditsPayload {
    credits: Option<f64>,
    delta: Option<f64>,
    unlimited: Option<bool>,
}

impl UserRecord {
    fn into_response(self) -> Result<UserResponse, AppError> {
        let role = UserRole::from_db(&self.role)?;
        Ok(UserResponse {
            id: self.id,
            email: self.email,
            role,
            active: self.active,
            credits: self.credits,
            unlimited: self.unlimited,
            created_at: format_timestamp(self.created_at)?,
        })
    }

    fn into_profile_response(self) -> Result<ProfileResponse, AppError> {
        let role = UserRole::from_db(&self.role)?;
        Ok(ProfileResponse {
            id: self.id,
            email: self.email,
            role,
            active: self.active,
            credits: self.credits,
            unlimited: self.unlimited,
        })
    }

    fn into_admin_response(self) -> Result<AdminUserResponse, AppError> {
        let role = UserRole::from_db(&self.role)?;
        Ok(AdminUserResponse {
            id: self.id,
            email: self.email,
            role,
            active: self.active,
            credits: self.credits,
            unlimited: self.unlimited,
            created_at: format_timestamp(self.created_at)?,
        })
    }
}

#[derive(Debug, Clone, FromRow)]
struct SimulationRecord {
    id: i64,
    owner_id: i64,
    status: String,
    alias: Option<String>,
    created_at: i64,
    updated_at: i64,
}

#[derive(Serialize)]
struct SimulationResponse {
    id: i64,
    owner_id: i64,
    status: String,
    alias: Option<String>,
    created_at: String,
    updated_at: String,
}

impl SimulationRecord {
    fn into_response(self) -> Result<SimulationResponse, AppError> {
        Ok(SimulationResponse {
            id: self.id,
            owner_id: self.owner_id,
            status: self.status,
            alias: self.alias,
            created_at: format_timestamp(self.created_at)?,
            updated_at: format_timestamp(self.updated_at)?,
        })
    }
}

#[derive(Deserialize)]
struct RegisterPayload {
    email: String,
    password: String,
}

#[derive(Deserialize)]
struct LoginPayload {
    email: String,
    password: String,
}

#[derive(Deserialize)]
struct UpdateEmailPayload {
    new_email: String,
}

#[derive(Deserialize)]
struct UpdatePasswordPayload {
    old_password: String,
    new_password: String,
}

#[derive(Deserialize)]
struct SimulationCreatePayload {
    alias: Option<String>,
}

#[derive(Deserialize)]
struct SimulationUpdatePayload {
    alias: Option<String>,
}

#[derive(Deserialize)]
struct SimulationStartPayload {
    alias: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthClaims {
    sub: i64,
    role: String,
    exp: usize,
}

#[derive(Debug, Clone)]
struct AuthUser {
    user_id: i64,
    role: UserRole,
    unlimited: bool,
}

impl AuthUser {
    fn is_admin(&self) -> bool {
        self.role.is_admin()
    }

    fn has_unlimited_credits(&self) -> bool {
        self.unlimited
    }
}

fn extract_bearer_token(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    let token = trimmed.strip_prefix("Bearer ")?;
    let token = token.trim();
    if token.is_empty() {
        None
    } else {
        Some(token)
    }
}

async fn authenticate_token(state: &AppState, token: &str) -> Result<AuthUser, AppError> {
    let token_data = decode::<AuthClaims>(
        token,
        state.jwt_decoding_key.as_ref(),
        &Validation::default(),
    )
    .map_err(|_| AppError::unauthorized("Invalid or expired authentication token"))?;

    let user_record = fetch_user_by_id(&state.db_pool, token_data.claims.sub).await?;
    if !user_record.active {
        return Err(AppError::forbidden("Account deactivated"));
    }

    let role = UserRole::from_db(&user_record.role)?;

    Ok(AuthUser {
        user_id: user_record.id,
        role,
        unlimited: user_record.unlimited,
    })
}

fn current_user<B>(req: &Request<B>) -> Result<AuthUser, AppError> {
    req.extensions()
        .get::<AuthUser>()
        .cloned()
        .ok_or_else(|| AppError::unauthorized("Authentication required"))
}

async fn handle_auth_middleware(
    req: Request<Body>,
    next: Next,
    state: AppState,
    admin_only: bool,
) -> Result<Response, AppError> {
    let (mut parts, body) = req.into_parts();
    let auth = AuthUser::from_request_parts(&mut parts, &state).await?;

    if admin_only && !auth.is_admin() {
        return Err(AppError::forbidden("Admin access required"));
    }

    let mut request = Request::from_parts(parts, body);
    request.extensions_mut().insert(auth);

    Ok(next.run(request).await)
}

async fn require_bearer_auth(
    State(state): State<AppState>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    let header_value = req
        .headers()
        .get(header::AUTHORIZATION)
        .ok_or_else(|| AppError::unauthorized("Authorization header is required"))?;

    let header_str = header_value
        .to_str()
        .map_err(|_| AppError::unauthorized("Invalid Authorization header"))?;

    let token = extract_bearer_token(header_str)
        .ok_or_else(|| AppError::unauthorized("Invalid Authorization header"))?;

    let auth_user = authenticate_token(&state, token).await?;
    req.extensions_mut().insert(auth_user);
    let _ = current_user(&req)?;

    Ok(next.run(req).await)
}

async fn require_auth(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    handle_auth_middleware(req, next, state, false).await
}

async fn require_admin(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    handle_auth_middleware(req, next, state, true).await
}

fn normalize_email(input: &str) -> String {
    input.trim().to_lowercase()
}

fn format_timestamp(epoch_seconds: i64) -> Result<String, AppError> {
    let dt = Utc
        .timestamp_opt(epoch_seconds, 0)
        .single()
        .ok_or_else(|| AppError::internal(format!("Invalid timestamp value: {epoch_seconds}")))?;
    Ok(dt.to_rfc3339())
}

fn normalize_alias_required(value: &str) -> Result<String, AppError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(AppError::bad_request("Alias is required"));
    }
    if trimmed.len() > MAX_ALIAS_LENGTH {
        return Err(AppError::bad_request(format!(
            "Alias must be at most {MAX_ALIAS_LENGTH} characters"
        )));
    }
    Ok(trimmed.to_string())
}

fn normalize_alias_optional(value: Option<&str>) -> Result<Option<String>, AppError> {
    match value {
        None => Ok(None),
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                Ok(None)
            } else if trimmed.len() > MAX_ALIAS_LENGTH {
                Err(AppError::bad_request(format!(
                    "Alias must be at most {MAX_ALIAS_LENGTH} characters"
                )))
            } else {
                Ok(Some(trimmed.to_string()))
            }
        }
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        if let Some(existing) = parts.extensions.get::<AuthUser>() {
            return Ok(existing.clone());
        }

        if let Some(header_value) = parts.headers.get(header::AUTHORIZATION) {
            let header_str = header_value
                .to_str()
                .map_err(|_| AppError::unauthorized("Invalid Authorization header"))?;

            let token = extract_bearer_token(header_str)
                .ok_or_else(|| AppError::unauthorized("Invalid Authorization header"))?;

            let app_state = AppState::from_ref(state);
            return authenticate_token(&app_state, token).await;
        }

        let jar = CookieJar::from_request_parts(parts, state)
            .await
            .map_err(|_| AppError::unauthorized("Failed to read authentication cookie"))?;

        let cookie = jar
            .get(AUTH_COOKIE)
            .ok_or_else(|| AppError::unauthorized("Authentication required"))?;

        let app_state = AppState::from_ref(state);

        let token = cookie.value();
        authenticate_token(&app_state, token).await
    }
}

async fn fetch_user_by_email(
    pool: &SqlitePool,
    email: &str,
) -> Result<Option<UserRecord>, AppError> {
    query_as::<_, UserRecord>(
        "SELECT id, email, password_hash, role, active, credits, unlimited, created_at FROM users WHERE email = ?",
    )
    .bind(email)
    .fetch_optional(pool)
    .await
    .map_err(|err| AppError::internal(format!("Failed to load user by email: {err}")))
}

async fn fetch_user_by_id(pool: &SqlitePool, user_id: i64) -> Result<UserRecord, AppError> {
    query_as::<_, UserRecord>(
        "SELECT id, email, password_hash, role, active, credits, unlimited, created_at FROM users WHERE id = ?",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(|err| AppError::internal(format!("Failed to load user by id: {err}")))?
    .ok_or_else(|| AppError::unauthorized("User not found"))
}

async fn count_users(pool: &SqlitePool) -> Result<i64, AppError> {
    let (count,) = query_as::<_, (i64,)>("SELECT COUNT(1) FROM users")
        .fetch_one(pool)
        .await
        .map_err(|err| AppError::internal(format!("Failed to count users: {err}")))?;
    Ok(count)
}

async fn ensure_default_admin(pool: &SqlitePool, email: &str, password: &str) -> Result<()> {
    let normalized_email = normalize_email(email);
    if normalized_email.is_empty() {
        bail!("DEFAULT_ADMIN_EMAIL must not be empty");
    }

    let existing = query_as::<_, (i64,)>("SELECT id FROM users WHERE email = ?")
        .bind(&normalized_email)
        .fetch_optional(pool)
        .await?;

    if existing.is_some() {
        return Ok(());
    }

    if password.trim().is_empty() {
        bail!("DEFAULT_ADMIN_PASSWORD must not be empty");
    }

    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|err| anyhow!("Failed to hash default admin password: {err}"))?
        .to_string();

    query(
        "INSERT INTO users (email, password_hash, role, credits, unlimited) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&normalized_email)
    .bind(password_hash)
    .bind(ROLE_ADMIN)
    .bind(DEFAULT_USER_CREDITS)
    .bind(0)
    .execute(pool)
    .await?;

    info!(
        "Created default admin account {normalized_email}. Please change the password immediately."
    );
    Ok(())
}

fn create_jwt(
    state: &AppState,
    user_id: i64,
    role: UserRole,
) -> Result<(String, OffsetDateTime), AppError> {
    let expires_at = Utc::now()
        .checked_add_signed(Duration::seconds(state.jwt_ttl_seconds))
        .ok_or_else(|| AppError::internal("Failed to compute token expiration time"))?
        .timestamp();

    let claims = AuthClaims {
        sub: user_id,
        role: role.as_str().to_string(),
        exp: expires_at as usize,
    };

    let token = encode(&Header::default(), &claims, state.jwt_encoding_key.as_ref())
        .map_err(|err| AppError::internal(format!("Failed to encode auth token: {err}")))?;

    let expires = OffsetDateTime::from_unix_timestamp(expires_at)
        .map_err(|err| AppError::internal(format!("Invalid token expiration timestamp: {err}")))?;

    Ok((token, expires))
}

fn build_auth_cookie(token: String, expires: OffsetDateTime) -> Cookie<'static> {
    Cookie::build((AUTH_COOKIE, token))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .expires(expires)
        .build()
}

fn clear_auth_cookie() -> Cookie<'static> {
    Cookie::build((AUTH_COOKIE, ""))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .expires(OffsetDateTime::UNIX_EPOCH)
        .build()
}

async fn ensure_setting(pool: &SqlitePool, key: &str, default_value: &str) -> Result<()> {
    query("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO NOTHING")
        .bind(key)
        .bind(default_value)
        .execute(pool)
        .await?;
    Ok(())
}

async fn set_bool_setting(pool: &SqlitePool, key: &str, value: bool) -> Result<(), AppError> {
    let stored = if value { "true" } else { "false" };
    query("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
        .bind(key)
        .bind(stored)
        .execute(pool)
        .await
        .map_err(|err| AppError::internal(format!("Failed to persist setting {key}: {err}")))?;
    Ok(())
}

async fn get_bool_setting(pool: &SqlitePool, key: &str, default: bool) -> Result<bool, AppError> {
    let result = query_as::<_, (String,)>("SELECT value FROM settings WHERE key = ?")
        .bind(key)
        .fetch_optional(pool)
        .await
        .map_err(|err| AppError::internal(format!("Failed to fetch setting {key}: {err}")))?;

    match result {
        None => Ok(default),
        Some((value,)) => Ok(value.eq_ignore_ascii_case("true")),
    }
}

async fn ensure_default_settings(pool: &SqlitePool) -> Result<()> {
    ensure_setting(pool, SETTING_ALLOW_SIGNUPS, "true").await?;
    ensure_setting(pool, SETTING_MAIL_BASE_URL, "").await?;
    Ok(())
}

async fn set_string_setting(pool: &SqlitePool, key: &str, value: &str) -> Result<(), AppError> {
    query("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
        .bind(key)
        .bind(value)
        .execute(pool)
        .await
        .map_err(|err| AppError::internal(format!("Failed to persist setting {key}: {err}")))?;
    Ok(())
}

async fn get_string_setting(pool: &SqlitePool, key: &str) -> Result<Option<String>, AppError> {
    let result = query_as::<_, (String,)>("SELECT value FROM settings WHERE key = ?")
        .bind(key)
        .fetch_optional(pool)
        .await
        .map_err(|err| AppError::internal(format!("Failed to fetch setting {key}: {err}")))?;

    Ok(result.map(|(value,)| value))
}

fn count_elements_in_inp(source: &str) -> usize {
    parse_inp_block_entries(source, "*ELEMENT")
}

fn count_nodes_in_inp(source: &str) -> usize {
    parse_inp_block_entries(source, "*NODE")
}

fn parse_inp_block_entries(source: &str, block_header: &str) -> usize {
    let mut in_block = false;
    let mut count = 0usize;
    let target = block_header.to_ascii_uppercase();

    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("**") {
            continue;
        }

        if trimmed.starts_with('*') {
            let upper = trimmed.to_ascii_uppercase();
            in_block = upper.starts_with(&target);
            continue;
        }

        if in_block {
            count = count.saturating_add(1);
        }
    }

    count
}

async fn load_benchmark_score(pool: &SqlitePool, fallback: f64) -> Result<f64, AppError> {
    match get_string_setting(pool, SETTING_BENCHMARK_SCORE).await? {
        Some(raw) => {
            let trimmed = raw.trim();
            match trimmed.parse::<f64>() {
                Ok(value) if value.is_finite() && value > 0.0 => Ok(value),
                Ok(_) => {
                    error!("Stored benchmark score is non-positive or invalid: {trimmed}");
                    Ok(fallback)
                }
                Err(err) => {
                    error!("Failed to parse stored benchmark score ({trimmed}): {err}");
                    Ok(fallback)
                }
            }
        }
        None => Ok(fallback),
    }
}

async fn debit_user_credits(pool: &SqlitePool, user_id: i64, amount: f64) -> Result<f64, AppError> {
    let record = query_as::<_, (f64, bool)>("SELECT credits, unlimited FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .map_err(|err| AppError::internal(format!("Failed to read user credits: {err}")))?;

    let (current_credits, unlimited) = match record {
        Some(record) => record,
        None => return Err(AppError::not_found("User not found")),
    };

    if unlimited || !amount.is_finite() || amount <= CREDIT_BALANCE_EPSILON {
        return Ok(current_credits);
    }

    let updated = query_as::<_, (f64,)>(
        "UPDATE users SET credits = credits - ? WHERE id = ? AND unlimited = 0 AND credits >= ? RETURNING credits",
    )
    .bind(amount)
    .bind(user_id)
    .bind(amount)
    .fetch_optional(pool)
    .await
    .map_err(|err| AppError::internal(format!("Failed to debit credits: {err}")))?;

    if let Some((balance,)) = updated {
        return Ok(balance.max(0.0));
    }

    if current_credits + CREDIT_BALANCE_EPSILON < amount {
        Err(AppError::payment_required(
            "Not enough credits to start simulation",
        ))
    } else {
        Err(AppError::internal(
            "Failed to debit credits despite sufficient balance",
        ))
    }
}

async fn credit_user_credits(
    pool: &SqlitePool,
    user_id: i64,
    amount: f64,
) -> Result<f64, AppError> {
    if !amount.is_finite() || amount <= CREDIT_BALANCE_EPSILON {
        let record = query_as::<_, (f64,)>("SELECT credits FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_optional(pool)
            .await
            .map_err(|err| AppError::internal(format!("Failed to read user credits: {err}")))?;

        return record
            .map(|(value,)| value)
            .ok_or_else(|| AppError::not_found("User not found"));
    }

    let updated = query_as::<_, (f64,)>(
        "UPDATE users SET credits = credits + ? WHERE id = ? RETURNING credits",
    )
    .bind(amount)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(|err| AppError::internal(format!("Failed to credit user: {err}")))?;

    updated
        .map(|(balance,)| balance)
        .ok_or_else(|| AppError::not_found("User not found"))
}

fn auth_routes() -> Router<AppState> {
    Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/me", get(me))
}

fn simulations_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/simulations",
            get(list_simulations).post(create_simulation),
        )
        .route(
            "/simulations/:id",
            patch(update_simulation).delete(delete_simulation),
        )
        .route("/simulations/send", post(send_simulation))
        .route("/simulations/start", post(start_simulation))
}

fn core_api_router() -> Router<AppState> {
    auth_routes().merge(simulations_routes())
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

    let data_root = PathBuf::from(env::var("DATA_ROOT").unwrap_or_else(|_| "/data".to_string()));
    let jobs_dir = data_root.join("jobs");
    fs::create_dir_all(&jobs_dir)
        .await
        .context("Failed to ensure /data/jobs directory exists")?;

    let config_dir = data_root.join("config");
    fs::create_dir_all(&config_dir)
        .await
        .context("Failed to ensure /data/config directory exists")?;

    let smtp_config_path = config_dir.join("smtp.json");
    let initial_smtp_config = load_smtp_config_from_disk(&smtp_config_path)
        .await
        .map_err(|err| anyhow!("Failed to load SMTP config: {}", err.message))?;

    let email_template_base = [
        PathBuf::from(EMAIL_TEMPLATE_DIR),
        PathBuf::from("app/templates/email"),
        PathBuf::from("../app/templates/email"),
        PathBuf::from("templates/email"),
        PathBuf::from("../templates/email"),
        PathBuf::from("backend/templates/email"),
    ]
    .into_iter()
    .find(|dir| dir.is_dir())
    .ok_or_else(|| {
        anyhow!("Email templates directory not found (expected at {EMAIL_TEMPLATE_DIR})")
    })?;

    let email_templates = EmailTemplateEngine::new(&email_template_base)
        .map_err(|err| anyhow!("Failed to initialise email templates: {}", err.message))?;

    let mail_log_path = data_root.join("mail.log");

    let ccx_threads = env::var("CCX_THREADS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|threads| *threads > 0)
        .unwrap_or(8);

    let frontend_dir =
        PathBuf::from(env::var("FRONTEND_DIST").unwrap_or_else(|_| "frontend/build".into()));

    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| format!("sqlite://{}", data_root.join("app.db").display()));

    if let Some(sqlite_path) = database_url.strip_prefix("sqlite://") {
        if let Some(parent) = Path::new(sqlite_path).parent() {
            fs::create_dir_all(parent).await.with_context(|| {
                format!("Failed to ensure database directory {}", parent.display())
            })?;
        }
    }

    let connect_options = SqliteConnectOptions::from_str(&database_url)
        .context("Failed to parse DATABASE_URL")?
        .create_if_missing(true);

    let db_pool = SqlitePoolOptions::new()
        .max_connections(10)
        .connect_with(connect_options)
        .await
        .context("Failed to connect to database")?;

    sqlx::migrate!("./migrations")
        .run(&db_pool)
        .await
        .context("Failed to run database migrations")?;

    ensure_default_settings(&db_pool)
        .await
        .context("Failed to ensure default application settings")?;

    let mail_base_url = get_string_setting(&db_pool, SETTING_MAIL_BASE_URL)
        .await
        .map_err(|err| anyhow!("Failed to load mail base URL: {}", err.message))?
        .and_then(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.trim_end_matches('/').trim().to_string())
            }
        });

    let admin_email =
        env::var("DEFAULT_ADMIN_EMAIL").unwrap_or_else(|_| "admin@mail.com".to_string());
    let admin_password = env::var("DEFAULT_ADMIN_PASSWORD").unwrap_or_else(|_| "admin".to_string());

    ensure_default_admin(&db_pool, &admin_email, &admin_password)
        .await
        .context("Failed to ensure default admin account")?;

    info!("Connected to database at {}", database_url);

    let jwt_secret =
        env::var("JWT_SECRET").unwrap_or_else(|_| "development-secret-change-me".to_string());

    if jwt_secret == "development-secret-change-me" {
        info!("JWT_SECRET not set, using development default (do not use in production)");
    }

    let jwt_encoding_key = Arc::new(EncodingKey::from_secret(jwt_secret.as_bytes()));
    let jwt_decoding_key = Arc::new(DecodingKey::from_secret(jwt_secret.as_bytes()));
    let jwt_ttl_seconds = env::var("JWT_TTL_SECONDS")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|ttl| *ttl > 0)
        .unwrap_or(60 * 60 * 24);

    let max_upload_bytes = resolve_upload_limit_bytes()?;
    info!(
        "Configured upload limit: {:.2} GiB",
        max_upload_bytes as f64 / (1024f64 * 1024f64 * 1024f64)
    );

    let state = AppState {
        jobs: Arc::new(RwLock::new(HashMap::new())),
        jobs_dir: Arc::new(jobs_dir.clone()),
        ccx_threads,
        db_pool,
        jwt_encoding_key,
        jwt_decoding_key,
        jwt_ttl_seconds,
        smtp_config_path: Arc::new(smtp_config_path),
        smtp_config: Arc::new(RwLock::new(initial_smtp_config)),
        email_templates,
        mail_log_path: Arc::new(mail_log_path),
        mail_base_url: Arc::new(RwLock::new(mail_base_url)),
        max_upload_bytes,
    };

    let upload_router = Router::new()
        .route("/upload", post(upload))
        .route("/status", get(status))
        .route("/download/:id", get(download))
        .route("/jobs/:id/cancel", post(cancel_job))
        .route("/jobs/estimate", post(estimate_job_upload_preview))
        .route("/jobs/:id", delete(delete_job))
        .layer(DefaultBodyLimit::max(max_upload_bytes))
        .route_layer(from_fn_with_state(state.clone(), require_auth));

    let profile_router = Router::new()
        .route("/", get(profile))
        .route("/update_email", post(update_profile_email))
        .route("/update_password", post(update_profile_password))
        .route_layer(from_fn_with_state(state.clone(), require_auth));

    let admin_router = Router::new()
        .route("/users", get(admin_list_users))
        .route("/users/:id/toggle_active", post(admin_toggle_user_active))
        .route("/users/:id", delete(admin_delete_user))
        .route(
            "/users/:id/credits",
            get(admin_get_user_credits).post(admin_update_user_credits),
        )
        .route("/benchmark", get(admin_get_benchmark))
        .route("/benchmark/run", post(admin_run_benchmark))
        .nest(
            "/settings",
            Router::new().route("/", get(admin_get_settings).post(admin_update_settings)),
        )
        .route("/smtp", get(admin_get_smtp_config))
        .route("/smtp/save", post(admin_save_smtp_config))
        .route("/smtp/test", post(admin_send_smtp_test))
        .route("/mail/log", get(admin_get_mail_log))
        .route_layer(from_fn_with_state(state.clone(), require_admin));

    let public_settings_router = Router::new().route("/", get(public_settings));

    let simulations_router = simulations_routes()
        .layer(DefaultBodyLimit::max(max_upload_bytes))
        .route_layer(from_fn_with_state(state.clone(), require_bearer_auth));

    let api_router = Router::new()
        .route("/auth/login", post(api_login))
        .merge(auth_routes())
        .merge(simulations_router)
        .nest("/profile", profile_router)
        .nest("/admin", admin_router)
        .nest("/settings", public_settings_router)
        .merge(
            Router::new()
                .route("/jobs/:id/estimate", get(estimate_job_credits))
                .route_layer(from_fn_with_state(state.clone(), require_auth)),
        );

    let legacy_router = core_api_router().layer(DefaultBodyLimit::max(max_upload_bytes));

    let static_service = ServeDir::new(frontend_dir.clone())
        .not_found_service(ServeFile::new(frontend_dir.join("index.html")));

    let app = Router::new()
        .merge(upload_router)
        .merge(legacy_router)
        .nest("/api", api_router)
        .fallback_service(static_service)
        .with_state(state);

    let addr: SocketAddr = env::var("APP_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
        .parse()
        .context("Invalid APP_ADDR value")?;

    info!("Starting server on {addr}");
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}

async fn register(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<RegisterPayload>,
) -> Result<(CookieJar, Json<UserResponse>), AppError> {
    let RegisterPayload {
        email: raw_email,
        password,
    } = payload;

    let email = normalize_email(&raw_email);
    if email.is_empty() || !email.contains('@') {
        return Err(AppError::bad_request("A valid email address is required"));
    }

    if password.trim().len() < PASSWORD_MIN_LEN {
        return Err(AppError::bad_request(format!(
            "Password must be at least {PASSWORD_MIN_LEN} characters long"
        )));
    }

    if count_users(&state.db_pool).await? > 0 {
        let allow_signups = get_bool_setting(&state.db_pool, SETTING_ALLOW_SIGNUPS, true).await?;
        if !allow_signups {
            return Err(AppError::forbidden(
                "Sign ups are currently disabled by an administrator",
            ));
        }
    }

    if fetch_user_by_email(&state.db_pool, &email).await?.is_some() {
        return Err(AppError::bad_request(
            "An account with that email already exists",
        ));
    }

    let target_role = if count_users(&state.db_pool).await? == 0 {
        UserRole::Admin
    } else {
        UserRole::User
    };

    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|err| AppError::internal(format!("Failed to hash password: {err}")))?
        .to_string();

    let result = query(
        "INSERT INTO users (email, password_hash, role, credits, unlimited) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&email)
    .bind(&password_hash)
    .bind(target_role.as_str())
    .bind(DEFAULT_USER_CREDITS)
    .bind(0)
    .execute(&state.db_pool)
    .await
    .map_err(|err| AppError::internal(format!("Failed to create user: {err}")))?;

    let user_id = result.last_insert_rowid();
    let user_record = fetch_user_by_id(&state.db_pool, user_id).await?;
    let user_response = user_record.clone().into_response()?;

    let (token, expires) = create_jwt(&state, user_record.id, target_role)?;
    let cookie = build_auth_cookie(token, expires);
    let jar = jar.add(cookie);

    Ok((jar, Json(user_response)))
}

async fn authenticate_user(
    state: &AppState,
    email: &str,
    password: &str,
    failure_message: &'static str,
) -> Result<(UserRecord, UserRole), AppError> {
    let user_record = fetch_user_by_email(&state.db_pool, email)
        .await?
        .ok_or_else(|| AppError::unauthorized(failure_message))?;

    if !user_record.active {
        return Err(AppError::forbidden("Account deactivated"));
    }

    let parsed_hash = PasswordHash::new(&user_record.password_hash)
        .map_err(|err| AppError::internal(format!("Invalid stored password hash: {err}")))?;

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .map_err(|_| AppError::unauthorized(failure_message))?;

    let role = UserRole::from_db(&user_record.role)?;

    Ok((user_record, role))
}

async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<LoginPayload>,
) -> Result<(CookieJar, Json<UserResponse>), AppError> {
    let LoginPayload {
        email: raw_email,
        password,
    } = payload;

    let email = normalize_email(&raw_email);
    if email.is_empty() {
        return Err(AppError::bad_request("Email is required"));
    }

    let (user_record, role) =
        authenticate_user(&state, &email, &password, "Invalid email or password").await?;

    let (token, expires) = create_jwt(&state, user_record.id, role)?;
    let cookie = build_auth_cookie(token, expires);
    let jar = jar.add(cookie);

    let user_response = user_record.into_response()?;
    Ok((jar, Json(user_response)))
}

async fn api_login(
    State(state): State<AppState>,
    Json(payload): Json<LoginPayload>,
) -> Result<Json<AuthLoginResponse>, AppError> {
    let LoginPayload {
        email: raw_email,
        password,
    } = payload;

    let email = normalize_email(&raw_email);
    if email.is_empty() || password.is_empty() {
        return Err(AppError::unauthorized("Invalid credentials"));
    }

    let (user_record, role) =
        authenticate_user(&state, &email, &password, "Invalid credentials").await?;

    let (token, _) = create_jwt(&state, user_record.id, role)?;

    let response = AuthLoginResponse {
        access_token: token,
        user: AuthUserSummary {
            id: user_record.id,
            email: user_record.email,
        },
    };

    Ok(Json(response))
}

async fn logout(jar: CookieJar) -> Result<(CookieJar, StatusCode), AppError> {
    let jar = jar.add(clear_auth_cookie());
    Ok((jar, StatusCode::NO_CONTENT))
}

async fn me(State(state): State<AppState>, auth: AuthUser) -> Result<Json<UserResponse>, AppError> {
    let record = fetch_user_by_id(&state.db_pool, auth.user_id).await?;
    let response = record.into_response()?;
    Ok(Json(response))
}

async fn profile(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<ProfileResponse>, AppError> {
    let record = fetch_user_by_id(&state.db_pool, auth.user_id).await?;
    Ok(Json(record.into_profile_response()?))
}

async fn update_profile_email(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(payload): Json<UpdateEmailPayload>,
) -> Result<Json<ProfileResponse>, AppError> {
    let new_email = normalize_email(&payload.new_email);
    if new_email.is_empty() || !new_email.contains('@') {
        return Err(AppError::bad_request("A valid email address is required"));
    }

    if let Some(existing) = fetch_user_by_email(&state.db_pool, &new_email).await? {
        if existing.id != auth.user_id {
            return Err(AppError::bad_request("Email is already in use"));
        }
    }

    query("UPDATE users SET email = ? WHERE id = ?")
        .bind(&new_email)
        .bind(auth.user_id)
        .execute(&state.db_pool)
        .await
        .map_err(|err| AppError::internal(format!("Failed to update email: {err}")))?;

    let record = fetch_user_by_id(&state.db_pool, auth.user_id).await?;
    Ok(Json(record.into_profile_response()?))
}

async fn update_profile_password(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(payload): Json<UpdatePasswordPayload>,
) -> Result<StatusCode, AppError> {
    let UpdatePasswordPayload {
        old_password,
        new_password,
    } = payload;

    if new_password.trim().len() < PASSWORD_MIN_LEN {
        return Err(AppError::bad_request(format!(
            "Password must be at least {PASSWORD_MIN_LEN} characters long"
        )));
    }

    if old_password.trim().is_empty() {
        return Err(AppError::bad_request("Current password is required"));
    }

    if old_password == new_password {
        return Err(AppError::bad_request(
            "New password must be different from the current password",
        ));
    }

    let record = fetch_user_by_id(&state.db_pool, auth.user_id).await?;

    let parsed_hash = PasswordHash::new(&record.password_hash)
        .map_err(|err| AppError::internal(format!("Invalid stored password hash: {err}")))?;

    Argon2::default()
        .verify_password(old_password.as_bytes(), &parsed_hash)
        .map_err(|_| AppError::bad_request("Current password is incorrect"))?;

    let salt = SaltString::generate(&mut OsRng);
    let new_password_hash = Argon2::default()
        .hash_password(new_password.as_bytes(), &salt)
        .map_err(|err| AppError::internal(format!("Failed to hash password: {err}")))?
        .to_string();

    query("UPDATE users SET password_hash = ? WHERE id = ?")
        .bind(new_password_hash)
        .bind(auth.user_id)
        .execute(&state.db_pool)
        .await
        .map_err(|err| AppError::internal(format!("Failed to update password: {err}")))?;

    Ok(StatusCode::NO_CONTENT)
}

async fn admin_list_users(
    State(state): State<AppState>,
) -> Result<Json<Vec<AdminUserResponse>>, AppError> {
    let users = query_as::<_, UserRecord>(
        "SELECT id, email, password_hash, role, active, credits, unlimited, created_at FROM users ORDER BY created_at DESC",
    )
    .fetch_all(&state.db_pool)
    .await
    .map_err(|err| AppError::internal(format!("Failed to list users: {err}")))?;

    let response = users
        .into_iter()
        .map(|record| record.into_admin_response())
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Json(response))
}

async fn load_settings(pool: &SqlitePool) -> Result<SettingsResponse, AppError> {
    let allow_signups = get_bool_setting(pool, SETTING_ALLOW_SIGNUPS, true).await?;
    let mail_base_url = match get_string_setting(pool, SETTING_MAIL_BASE_URL).await? {
        Some(value) => match normalize_mail_base_url(&value) {
            Ok(result) => result,
            Err(err) => {
                warn!("Stored mail base URL is invalid: {}", err.message);
                None
            }
        },
        None => None,
    };

    Ok(SettingsResponse {
        allow_signups,
        mail_base_url,
    })
}

async fn public_settings(
    State(state): State<AppState>,
) -> Result<Json<SettingsResponse>, AppError> {
    Ok(Json(load_settings(&state.db_pool).await?))
}

async fn admin_get_settings(
    State(state): State<AppState>,
) -> Result<Json<SettingsResponse>, AppError> {
    Ok(Json(load_settings(&state.db_pool).await?))
}

async fn admin_update_settings(
    State(state): State<AppState>,
    Json(payload): Json<UpdateSettingsPayload>,
) -> Result<Json<SettingsResponse>, AppError> {
    if let Some(value) = payload.allow_signups {
        set_bool_setting(&state.db_pool, SETTING_ALLOW_SIGNUPS, value).await?;
    }

    if let Some(raw_base_url) = payload.mail_base_url {
        let normalized = normalize_mail_base_url(&raw_base_url)?;
        let stored = normalized.clone().unwrap_or_default();
        set_string_setting(&state.db_pool, SETTING_MAIL_BASE_URL, &stored).await?;

        let mut guard = state.mail_base_url.write().await;
        *guard = normalized;
    }

    Ok(Json(load_settings(&state.db_pool).await?))
}

async fn admin_get_smtp_config(
    State(state): State<AppState>,
) -> Result<Json<SmtpConfig>, AppError> {
    let current = state
        .smtp_config
        .read()
        .await
        .clone()
        .unwrap_or_else(SmtpConfig::default);
    Ok(Json(current))
}

async fn admin_save_smtp_config(
    State(state): State<AppState>,
    Json(payload): Json<SmtpConfigInput>,
) -> Result<Json<SmtpConfig>, AppError> {
    let config = normalize_smtp_config(payload)?;
    persist_smtp_config(&state.smtp_config_path, &config).await?;

    {
        let mut guard = state.smtp_config.write().await;
        *guard = Some(config.clone());
    }

    info!("SMTP configuration updated");
    Ok(Json(config))
}

async fn admin_send_smtp_test(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<StatusCode, AppError> {
    let recipient = fetch_user_by_id(&state.db_pool, auth.user_id).await?.email;

    send_smtp_test_email(&state, &recipient).await?;
    info!("SMTP test email triggered for {recipient}");

    Ok(StatusCode::NO_CONTENT)
}

async fn admin_get_mail_log(
    State(state): State<AppState>,
) -> Result<Json<Vec<MailLogEntry>>, AppError> {
    let data = match fs::read(state.mail_log_path.as_ref()).await {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(Json(Vec::new())),
        Err(err) => {
            return Err(AppError::internal(format!(
                "Failed to read mail log: {err}"
            )))
        }
    };

    if data.is_empty() {
        return Ok(Json(Vec::new()));
    }

    let content = String::from_utf8(data)
        .map_err(|err| AppError::internal(format!("Mail log contains invalid UTF-8: {err}")))?;

    let mut entries = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        match serde_json::from_str::<MailLogEntry>(trimmed) {
            Ok(entry) => entries.push(entry),
            Err(err) => warn!("Failed to parse mail log entry: {err}"),
        }
    }

    let recent: Vec<MailLogEntry> = entries.into_iter().rev().take(20).collect();
    Ok(Json(recent))
}

async fn admin_get_user_credits(
    State(state): State<AppState>,
    AxumPath(user_id): AxumPath<i64>,
) -> Result<Json<UserCreditsResponse>, AppError> {
    let record = match fetch_user_by_id(&state.db_pool, user_id).await {
        Ok(record) => record,
        Err(err) if err.status == StatusCode::UNAUTHORIZED => {
            return Err(AppError::not_found("User not found"));
        }
        Err(err) => return Err(err),
    };

    Ok(Json(UserCreditsResponse {
        id: record.id,
        email: record.email,
        credits: record.credits,
        unlimited: record.unlimited,
    }))
}

async fn admin_update_user_credits(
    State(state): State<AppState>,
    AxumPath(user_id): AxumPath<i64>,
    Json(payload): Json<AdjustCreditsPayload>,
) -> Result<Json<UserCreditsResponse>, AppError> {
    let mut record = match fetch_user_by_id(&state.db_pool, user_id).await {
        Ok(record) => record,
        Err(err) if err.status == StatusCode::UNAUTHORIZED => {
            return Err(AppError::not_found("User not found"));
        }
        Err(err) => return Err(err),
    };

    if payload.credits.is_some() && payload.delta.is_some() {
        return Err(AppError::bad_request(
            "Provide either 'credits' or 'delta', not both",
        ));
    }

    let target_unlimited = payload.unlimited.unwrap_or(record.unlimited);

    let mut target_credits = record.credits;

    if target_unlimited {
        // Unlimited users keep their current balance (for reference only).
        target_credits = record.credits;
    } else {
        if let Some(value) = payload.credits {
            target_credits = value;
        } else if let Some(delta) = payload.delta {
            target_credits = record.credits + delta;
        } else if record.unlimited && payload.unlimited == Some(false) {
            // Switching off unlimited without specifying a target amount.
            target_credits = DEFAULT_USER_CREDITS;
        }

        if !target_credits.is_finite() || target_credits < 0.0 {
            return Err(AppError::bad_request(
                "Credits must be a non-negative finite number",
            ));
        }
    }

    query("UPDATE users SET credits = ?, unlimited = ? WHERE id = ?")
        .bind(target_credits)
        .bind(if target_unlimited { 1 } else { 0 })
        .bind(user_id)
        .execute(&state.db_pool)
        .await
        .map_err(|err| AppError::internal(format!("Failed to update credits: {err}")))?;

    record.credits = target_credits;
    record.unlimited = target_unlimited;

    Ok(Json(UserCreditsResponse {
        id: record.id,
        email: record.email,
        credits: record.credits,
        unlimited: record.unlimited,
    }))
}

async fn admin_get_benchmark(
    State(state): State<AppState>,
) -> Result<Json<BenchmarkResponse>, AppError> {
    let raw_score = get_string_setting(&state.db_pool, SETTING_BENCHMARK_SCORE).await?;
    let raw_recorded_at = get_string_setting(&state.db_pool, SETTING_BENCHMARK_RECORDED_AT).await?;

    let score_seconds = raw_score.as_deref().and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            match trimmed.parse::<f64>() {
                Ok(parsed) => Some(parsed),
                Err(err) => {
                    error!("Stored benchmark score is invalid ({trimmed}): {err}");
                    None
                }
            }
        }
    });

    let recorded_at = raw_recorded_at
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string());

    Ok(Json(BenchmarkResponse {
        score_seconds,
        recorded_at,
    }))
}

async fn admin_run_benchmark(
    State(state): State<AppState>,
) -> Result<Json<BenchmarkResponse>, AppError> {
    let benchmark_path = {
        let candidates = [
            PathBuf::from(BENCHMARK_INPUT_PATH),
            PathBuf::from("benchmark.inp"),
            PathBuf::from("backend/benchmark.inp"),
        ];

        candidates
            .into_iter()
            .find(|path| path.exists())
            .ok_or_else(|| {
                AppError::internal(format!(
                    "Benchmark input file not found (expected at {BENCHMARK_INPUT_PATH})"
                ))
            })?
    };

    let run_id = Uuid::new_v4();
    let run_dir = state.jobs_dir.join(format!("benchmark-{run_id}"));
    fs::create_dir_all(&run_dir).await.map_err(|err| {
        AppError::internal(format!("Failed to create benchmark directory: {err}"))
    })?;

    let model_path = run_dir.join("model.inp");
    fs::copy(&benchmark_path, &model_path)
        .await
        .map_err(|err| AppError::internal(format!("Failed to prepare benchmark input: {err}")))?;

    let log_path = run_dir.join("solver.log");

    let outcome: Result<f64, AppError> = async {
        let log_file = std::fs::File::create(&log_path)
            .map_err(|err| AppError::internal(format!("Failed to create benchmark log: {err}")))?;
        let log_file_err = log_file.try_clone().map_err(|err| {
            AppError::internal(format!("Failed to initialise benchmark log: {err}"))
        })?;

        let mut command = Command::new("ccx");
        command
            .arg("-i")
            .arg("model")
            .arg("-nt")
            .arg(state.ccx_threads.to_string())
            .current_dir(&run_dir)
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(log_file_err));

        info!("Starting benchmark run {run_id}");

        let start = Instant::now();
        let mut child = command
            .spawn()
            .map_err(|err| AppError::internal(format!("Failed to start benchmark: {err}")))?;
        let status = child
            .wait()
            .await
            .map_err(|err| AppError::internal(format!("Failed to await benchmark: {err}")))?;

        if !status.success() {
            return Err(AppError::internal(format!(
                "Benchmark failed with status: {status}"
            )));
        }

        Ok(start.elapsed().as_secs_f64())
    }
    .await;

    if let Err(err) = fs::remove_dir_all(&run_dir).await {
        error!(
            "Failed to clean up benchmark directory {}: {err}",
            run_dir.display()
        );
    }

    let elapsed = outcome?;
    let recorded_at = Utc::now().to_rfc3339();

    set_string_setting(
        &state.db_pool,
        SETTING_BENCHMARK_SCORE,
        &format!("{elapsed:.6}"),
    )
    .await?;
    set_string_setting(&state.db_pool, SETTING_BENCHMARK_RECORDED_AT, &recorded_at).await?;

    info!("Benchmark run {run_id} completed in {elapsed:.3} seconds (recorded at {recorded_at})");

    Ok(Json(BenchmarkResponse {
        score_seconds: Some(elapsed),
        recorded_at: Some(recorded_at),
    }))
}

async fn admin_toggle_user_active(
    State(state): State<AppState>,
    auth: AuthUser,
    AxumPath(user_id): AxumPath<i64>,
) -> Result<Json<AdminUserResponse>, AppError> {
    if user_id == auth.user_id {
        return Err(AppError::bad_request(
            "You cannot change your own active status",
        ));
    }

    let result =
        query("UPDATE users SET active = CASE WHEN active = 1 THEN 0 ELSE 1 END WHERE id = ?")
            .bind(user_id)
            .execute(&state.db_pool)
            .await
            .map_err(|err| AppError::internal(format!("Failed to toggle user status: {err}")))?;

    if result.rows_affected() == 0 {
        return Err(AppError::not_found("User not found"));
    }

    let record = fetch_user_by_id(&state.db_pool, user_id).await?;
    Ok(Json(record.into_admin_response()?))
}

async fn admin_delete_user(
    State(state): State<AppState>,
    auth: AuthUser,
    AxumPath(user_id): AxumPath<i64>,
) -> Result<StatusCode, AppError> {
    if user_id == auth.user_id {
        return Err(AppError::bad_request("You cannot delete your own account"));
    }

    let result = query("DELETE FROM users WHERE id = ?")
        .bind(user_id)
        .execute(&state.db_pool)
        .await
        .map_err(|err| AppError::internal(format!("Failed to delete user: {err}")))?;

    if result.rows_affected() == 0 {
        return Err(AppError::not_found("User not found"));
    }

    Ok(StatusCode::NO_CONTENT)
}

async fn list_simulations(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<SimulationResponse>>, AppError> {
    let simulations = if auth.is_admin() {
        query_as::<_, SimulationRecord>(
            "SELECT id, owner_id, status, alias, created_at, updated_at FROM simulations ORDER BY created_at DESC",
        )
        .fetch_all(&state.db_pool)
        .await
    } else {
        query_as::<_, SimulationRecord>(
            "SELECT id, owner_id, status, alias, created_at, updated_at FROM simulations WHERE owner_id = ? ORDER BY created_at DESC",
        )
        .bind(auth.user_id)
        .fetch_all(&state.db_pool)
        .await
    }
    .map_err(|err| AppError::internal(format!("Failed to list simulations: {err}")))?;

    let response = simulations
        .into_iter()
        .map(|record| record.into_response())
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Json(response))
}

async fn create_simulation(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(payload): Json<SimulationCreatePayload>,
) -> Result<(StatusCode, Json<SimulationResponse>), AppError> {
    // Ensure the user still exists; this can also surface role updates.
    let user_record = fetch_user_by_id(&state.db_pool, auth.user_id).await?;
    let alias = normalize_alias_optional(payload.alias.as_deref())?;

    let timestamp = Utc::now().timestamp();

    let result = query(
        "INSERT INTO simulations (owner_id, status, alias, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(user_record.id)
    .bind(DEFAULT_SIM_STATUS)
    .bind(alias.clone())
    .bind(timestamp)
    .bind(timestamp)
    .execute(&state.db_pool)
    .await
    .map_err(|err| AppError::internal(format!("Failed to create simulation: {err}")))?;

    let simulation_id = result.last_insert_rowid();

    let record = query_as::<_, SimulationRecord>(
        "SELECT id, owner_id, status, alias, created_at, updated_at FROM simulations WHERE id = ?",
    )
    .bind(simulation_id)
    .fetch_one(&state.db_pool)
    .await
    .map_err(|err| AppError::internal(format!("Failed to load simulation: {err}")))?;

    Ok((StatusCode::CREATED, Json(record.into_response()?)))
}

async fn delete_simulation(
    State(state): State<AppState>,
    auth: AuthUser,
    AxumPath(simulation_id): AxumPath<i64>,
) -> Result<StatusCode, AppError> {
    let record = query_as::<_, SimulationRecord>(
        "SELECT id, owner_id, status, alias, created_at, updated_at FROM simulations WHERE id = ?",
    )
    .bind(simulation_id)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|err| AppError::internal(format!("Failed to load simulation: {err}")))?
    .ok_or_else(|| AppError::not_found("Simulation not found"))?;

    if !auth.is_admin() && record.owner_id != auth.user_id {
        return Err(AppError::forbidden(
            "You are not allowed to delete this simulation",
        ));
    }

    query("DELETE FROM simulations WHERE id = ?")
        .bind(simulation_id)
        .execute(&state.db_pool)
        .await
        .map_err(|err| AppError::internal(format!("Failed to delete simulation: {err}")))?;

    Ok(StatusCode::NO_CONTENT)
}

async fn update_simulation(
    State(state): State<AppState>,
    auth: AuthUser,
    AxumPath(simulation_id): AxumPath<i64>,
    Json(payload): Json<SimulationUpdatePayload>,
) -> Result<Json<SimulationResponse>, AppError> {
    let existing = query_as::<_, SimulationRecord>(
        "SELECT id, owner_id, status, alias, created_at, updated_at FROM simulations WHERE id = ?",
    )
    .bind(simulation_id)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|err| AppError::internal(format!("Failed to load simulation: {err}")))?
    .ok_or_else(|| AppError::not_found("Simulation not found"))?;

    if !auth.is_admin() && existing.owner_id != auth.user_id {
        return Err(AppError::forbidden(
            "You are not allowed to edit this simulation",
        ));
    }

    let timestamp = Utc::now().timestamp();

    let alias = normalize_alias_optional(payload.alias.as_deref())?;

    query("UPDATE simulations SET alias = ?, updated_at = ? WHERE id = ?")
        .bind(alias.clone())
        .bind(timestamp)
        .bind(simulation_id)
        .execute(&state.db_pool)
        .await
        .map_err(|err| AppError::internal(format!("Failed to update simulation: {err}")))?;

    let updated = query_as::<_, SimulationRecord>(
        "SELECT id, owner_id, status, alias, created_at, updated_at FROM simulations WHERE id = ?",
    )
    .bind(simulation_id)
    .fetch_one(&state.db_pool)
    .await
    .map_err(|err| AppError::internal(format!("Failed to load simulation: {err}")))?;

    Ok(Json(updated.into_response()?))
}

async fn send_simulation(
    State(state): State<AppState>,
    auth: AuthUser,
    mut multipart: Multipart,
) -> Result<Json<SimulationSendResponse>, AppError> {
    let mut alias_raw: Option<String> = None;
    let mut alias_fallback: Option<String> = None;
    let mut file_saved = false;
    let mut total_bytes: usize = 0;
    let mut job_id: Option<Uuid> = None;
    let mut job_dir: Option<PathBuf> = None;
    let mut model_path: Option<PathBuf> = None;

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|err| AppError::internal(err.to_string()))?
    {
        let field_name = field.name().map(|value| value.to_string());
        match field_name.as_deref() {
            Some("alias") => {
                let value = field
                    .text()
                    .await
                    .map_err(|err| AppError::internal(format!("Failed to read alias: {err}")))?;
                alias_raw = Some(value);
            }
            Some("file") | None => {
                if file_saved {
                    return Err(AppError::bad_request(
                        "Multiple files provided; only one .inp file is allowed",
                    ));
                }

                let file_name =
                    field
                        .file_name()
                        .map(|name| name.to_string())
                        .ok_or_else(|| {
                            AppError::bad_request("Uploaded file must include a filename")
                        })?;

                if !file_name.to_ascii_lowercase().ends_with(".inp") {
                    return Err(AppError::bad_request("Only .inp files are accepted"));
                }

                if let Some(raw_alias) = Path::new(&file_name)
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .map(|stem| stem.trim().to_string())
                    .filter(|value| !value.is_empty())
                {
                    match normalize_alias_optional(Some(raw_alias.as_str())) {
                        Ok(sanitized) => {
                            alias_fallback = sanitized;
                        }
                        Err(err) => {
                            warn!(
                                "Discarding derived alias \"{}\" due to validation error: {}",
                                raw_alias, err.message
                            );
                            alias_fallback = None;
                        }
                    }
                }

                let current_job_id = job_id.get_or_insert_with(Uuid::new_v4).to_owned();
                let dir = match job_dir.clone() {
                    Some(dir) => dir,
                    None => {
                        let dir = state.jobs_dir.join(current_job_id.to_string());
                        fs::create_dir_all(&dir).await.map_err(|err| {
                            AppError::internal(format!("Failed to create job directory: {err}"))
                        })?;
                        job_dir = Some(dir.clone());
                        dir
                    }
                };

                let path = dir.join("model.inp");
                let mut file = fs::File::create(&path).await.map_err(|err| {
                    AppError::internal(format!("Failed to create model.inp: {err}"))
                })?;

                while let Some(chunk) = field.chunk().await.map_err(|err| {
                    AppError::internal(format!("Failed to read upload chunk: {err}"))
                })? {
                    if chunk.is_empty() {
                        continue;
                    }
                    total_bytes = total_bytes.saturating_add(chunk.len());
                    if total_bytes > state.max_upload_bytes {
                        drop(file);
                        if let Some(dir) = job_dir.as_ref() {
                            cleanup_job_directory(dir).await;
                        }
                        return Err(AppError::bad_request(
                            "Uploaded file exceeds maximum allowed size",
                        ));
                    }
                    file.write_all(&chunk).await.map_err(|err| {
                        AppError::internal(format!("Failed writing model.inp: {err}"))
                    })?;
                }

                if total_bytes == 0 {
                    drop(file);
                    if let Some(dir) = job_dir.as_ref() {
                        cleanup_job_directory(dir).await;
                    }
                    return Err(AppError::bad_request("Uploaded file is empty"));
                }

                file.flush().await.map_err(|err| {
                    AppError::internal(format!("Failed to flush model.inp: {err}"))
                })?;

                model_path = Some(path);
                file_saved = true;
            }
            Some(_) => {
                // Ignore unknown fields.
            }
        }
    }

    if !file_saved {
        return Err(AppError::bad_request(
            "Request must include a CalculiX .inp file",
        ));
    }

    let job_id = job_id.expect("job id set when file is saved");
    let job_dir = job_dir.expect("job dir set when file is saved");
    let model_path = model_path.expect("model path set when file is saved");

    let alias_optional = match normalize_alias_optional(alias_raw.as_deref()) {
        Ok(value) => value,
        Err(err) => {
            cleanup_job_directory(&job_dir).await;
            return Err(err);
        }
    };

    let estimator = CreditEstimator::default();
    let estimate = match estimator
        .estimate_from_input_file(&state.db_pool, &model_path)
        .await
    {
        Ok(value) => value,
        Err(err) => {
            cleanup_job_directory(&job_dir).await;
            return Err(err);
        }
    };

    let estimated_credits = if estimate.estimated_credits.is_finite() {
        estimate.estimated_credits.max(0.0)
    } else {
        0.0
    };

    if estimated_credits > 0.0 && !auth.is_admin() && !auth.has_unlimited_credits() {
        let user_record = match fetch_user_by_id(&state.db_pool, auth.user_id).await {
            Ok(record) => record,
            Err(err) => {
                cleanup_job_directory(&job_dir).await;
                return Err(err);
            }
        };

        if user_record.credits + CREDIT_BALANCE_EPSILON < estimated_credits {
            cleanup_job_directory(&job_dir).await;
            return Err(AppError::payment_required(
                "Not enough credits to start simulation",
            ));
        }
    }

    let alias_for_db = alias_optional.clone().or_else(|| alias_fallback.clone());
    let timestamp = Utc::now().timestamp();

    let insert_result = query(
        "INSERT INTO simulations (owner_id, status, alias, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(auth.user_id)
    .bind(DEFAULT_SIM_STATUS)
    .bind(alias_for_db.clone())
    .bind(timestamp)
    .bind(timestamp)
    .execute(&state.db_pool)
    .await;

    if let Err(err) = insert_result {
        cleanup_job_directory(&job_dir).await;
        return Err(AppError::internal(format!(
            "Failed to create simulation: {err}"
        )));
    }

    let detected_job_type = detect_job_type(&model_path).await.unwrap_or(None);

    let alias_response = alias_for_db.clone().unwrap_or_else(|| job_id.to_string());

    let job_entry = JobEntry {
        id: job_id,
        owner_id: auth.user_id,
        alias: alias_response.clone(),
        running: false,
        done: false,
        cancelled: false,
        started_at: Utc::now(),
        started_instant: Instant::now(),
        duration: None,
        job_type: detected_job_type,
        log_path: job_dir.join("solver.log"),
        job_dir: job_dir.clone(),
        error: None,
        cancel_token: None,
        element_count: estimate.element_count,
        estimated_runtime_seconds: estimate.estimated_runtime_seconds,
        benchmark_score: estimate.benchmark_score,
        estimated_credits,
        charged_credits: 0.0,
    };

    {
        let mut jobs = state.jobs.write().await;
        jobs.insert(job_id, job_entry);
    }

    let response = SimulationSendResponse {
        alias: alias_response,
        estimated_credits,
        estimated_time_s: estimate.estimated_runtime_seconds,
    };

    Ok(Json(response))
}

async fn start_simulation(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(payload): Json<SimulationStartPayload>,
) -> Result<Json<SimulationStartResponse>, AppError> {
    let SimulationStartPayload { alias } = payload;
    let normalized_alias = normalize_alias_required(&alias)?;

    let pending_job = {
        let jobs = state.jobs.read().await;
        jobs.iter()
            .find(|(_, entry)| {
                entry.owner_id == auth.user_id
                    && !entry.running
                    && !entry.done
                    && entry.alias == normalized_alias
            })
            .map(|(job_id, entry)| (*job_id, entry.clone()))
    };

    let (job_id, job_snapshot) =
        pending_job.ok_or_else(|| AppError::not_found("Pending simulation not found"))?;

    if job_snapshot.charged_credits > CREDIT_BALANCE_EPSILON {
        return Err(AppError::bad_request(
            "Simulation has already been charged for execution",
        ));
    }

    let model_path = job_snapshot.job_dir.join("model.inp");
    fs::metadata(&model_path)
        .await
        .map_err(|_| AppError::internal("Simulation input file missing"))?;

    let requires_charge = !(auth.is_admin() || auth.has_unlimited_credits());
    let mut charged_credits = 0.0;

    if requires_charge && job_snapshot.estimated_credits.is_finite() {
        let amount = job_snapshot.estimated_credits.max(0.0);
        if amount > CREDIT_BALANCE_EPSILON {
            debit_user_credits(&state.db_pool, auth.user_id, amount).await?;
            charged_credits = amount;
        }
    }

    let cancel_token = CancellationToken::new();
    let job_start_result = {
        let mut jobs = state.jobs.write().await;
        match jobs.get_mut(&job_id) {
            Some(entry) => {
                if entry.owner_id != auth.user_id || entry.alias != normalized_alias {
                    Err(AppError::not_found("Pending simulation not found"))
                } else if entry.running {
                    Err(AppError::bad_request("Simulation is already running"))
                } else if entry.done {
                    Err(AppError::bad_request("Simulation has already completed"))
                } else {
                    entry.running = true;
                    entry.done = false;
                    entry.cancelled = false;
                    entry.started_at = Utc::now();
                    entry.started_instant = Instant::now();
                    entry.duration = None;
                    entry.error = None;
                    entry.charged_credits = charged_credits;
                    entry.cancel_token = Some(cancel_token.clone());
                    Ok(entry.alias.clone())
                }
            }
            None => Err(AppError::not_found("Pending simulation not found")),
        }
    };

    let alias_for_response = match job_start_result {
        Ok(value) => value,
        Err(err) => {
            if charged_credits > CREDIT_BALANCE_EPSILON {
                if let Err(refund_err) =
                    credit_user_credits(&state.db_pool, auth.user_id, charged_credits).await
                {
                    warn!(
                        "Failed to refund credits after simulation start error for user {}: {:?}",
                        auth.user_id, refund_err
                    );
                }
            }
            return Err(err);
        }
    };

    info!(
        "User {} started simulation \"{}\" (job {}) using {:.3} credits",
        auth.user_id, alias_for_response, job_id, charged_credits
    );

    tokio::spawn(run_calculix_job(state.clone(), job_id, cancel_token));

    Ok(Json(SimulationStartResponse {
        status: "started".to_string(),
        alias: alias_for_response,
    }))
}

async fn upload(
    State(state): State<AppState>,
    auth: AuthUser,
    mut multipart: Multipart,
) -> Result<Json<UploadResponse>, AppError> {
    let mut alias: Option<String> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|err| AppError::internal(err.to_string()))?
    {
        let field_name = field.name().map(|value| value.to_string());
        match field_name.as_deref() {
            Some("alias") => {
                let value = field
                    .text()
                    .await
                    .map_err(|err| AppError::internal(format!("Failed to read alias: {err}")))?;
                let normalized = normalize_alias_required(&value)?;
                alias = Some(normalized);
            }
            Some("file") | None => {
                let file_field = field;
                let file_name = file_field
                    .file_name()
                    .map(|name| name.to_string())
                    .ok_or_else(|| {
                        AppError::bad_request("Uploaded file must include a filename")
                    })?;

                if !file_name.to_lowercase().ends_with(".inp") {
                    return Err(AppError::bad_request("Only .inp files are accepted"));
                }

                let alias = alias
                    .clone()
                    .ok_or_else(|| AppError::bad_request("Alias is required before uploading"))?;

                return process_inp_upload(file_field, state, auth.clone(), alias).await;
            }
            Some(_) => {
                // Ignore unknown fields.
            }
        }
    }

    Err(AppError::bad_request(
        "Upload must include alias and .inp file",
    ))
}

async fn cleanup_job_directory(path: &Path) {
    if let Err(err) = fs::remove_dir_all(path).await {
        if err.kind() != ErrorKind::NotFound {
            warn!("Failed to clean up job directory {}: {err}", path.display());
        }
    }
}

async fn process_inp_upload(
    mut field: Field<'_>,
    state: AppState,
    auth: AuthUser,
    alias: String,
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

    let estimator = CreditEstimator::default();
    let estimate = match estimator
        .estimate_from_input_file(&state.db_pool, &model_path)
        .await
    {
        Ok(value) => value,
        Err(err) => {
            if let Err(clean_err) = fs::remove_dir_all(&job_dir).await {
                if clean_err.kind() != std::io::ErrorKind::NotFound {
                    warn!(
                        "Failed to clean up job directory {} after estimate failure: {clean_err}",
                        job_dir.display()
                    );
                }
            }
            return Err(err);
        }
    };

    let estimated_credits = if estimate.estimated_credits.is_finite() {
        estimate.estimated_credits.max(0.0)
    } else {
        0.0
    };

    let has_free_credits = auth.is_admin() || auth.has_unlimited_credits();
    let charged_credits = if has_free_credits {
        0.0
    } else {
        estimated_credits
    };

    if charged_credits > CREDIT_BALANCE_EPSILON {
        match debit_user_credits(&state.db_pool, auth.user_id, charged_credits).await {
            Ok(balance) => info!(
                "User {} charged {:.3} credits for job {} (remaining {:.3})",
                auth.user_id, charged_credits, job_id, balance
            ),
            Err(err) => {
                if let Err(clean_err) = fs::remove_dir_all(&job_dir).await {
                    if clean_err.kind() != std::io::ErrorKind::NotFound {
                        warn!(
                            "Failed to clean up job directory {} after credit failure: {clean_err}",
                            job_dir.display()
                        );
                    }
                }
                return Err(err);
            }
        };
    } else if auth.is_admin() {
        info!(
            "Admin user {} started job {} without credit deduction (estimate {:.3} credits)",
            auth.user_id, job_id, estimated_credits
        );
    } else if auth.has_unlimited_credits() {
        info!(
            "User {} has unlimited credits; job {} not charged (estimate {:.3} credits)",
            auth.user_id, job_id, estimated_credits
        );
    }

    let detected_job_type = detect_job_type(&model_path).await.unwrap_or(None);

    let cancel_token = CancellationToken::new();

    let job_entry = JobEntry {
        id: job_id,
        owner_id: auth.user_id,
        alias: alias.clone(),
        running: true,
        done: false,
        cancelled: false,
        started_at: Utc::now(),
        started_instant: Instant::now(),
        duration: None,
        job_type: detected_job_type,
        log_path: job_dir.join("solver.log"),
        job_dir: job_dir.clone(),
        error: None,
        cancel_token: Some(cancel_token.clone()),
        element_count: estimate.element_count,
        estimated_runtime_seconds: estimate.estimated_runtime_seconds,
        benchmark_score: estimate.benchmark_score,
        estimated_credits,
        charged_credits,
    };

    {
        let mut jobs = state.jobs.write().await;
        jobs.insert(job_id, job_entry.clone());
    }

    tokio::spawn(run_calculix_job(state, job_id, cancel_token));

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

async fn run_calculix_job(state: AppState, job_id: Uuid, cancel_token: CancellationToken) {
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
    let execution = async {
        let mut completion_notification: Option<JobCompletionEmail> = None;
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
        let mut child = command
            .spawn()
            .context("Failed to spawn CalculiX process")?;
        let mut cancelled = false;

        let status = tokio::select! {
            status = child.wait() => {
                status.context("Failed to wait for CalculiX process")?
            }
            _ = cancel_token.cancelled() => {
                cancelled = true;
                // Attempt to terminate the process; ignore errors if already exited.
                if let Err(err) = child.kill().await {
                    if err.kind() != std::io::ErrorKind::InvalidInput {
                        error!("Failed to kill CalculiX job {job_id}: {err}");
                    }
                }
                child.wait().await.context("Failed to wait for cancelled CalculiX process")?
            }
        };

        let mut jobs = state.jobs.write().await;
        let mut refund: Option<(i64, f64)> = None;
        if let Some(entry) = jobs.get_mut(&job_id) {
            entry.running = false;
            entry.cancel_token = None;
            entry.duration = Some(entry.started_instant.elapsed().as_secs_f64());
            entry.cancelled = cancelled;

            if cancelled {
                entry.done = false;
                entry.error = None;
                info!("CalculiX job {job_id} cancelled by user");
            } else if status.success() {
                entry.done = true;
                entry.error = None;
                completion_notification = Some(JobCompletionEmail {
                    job_id,
                    owner_id: entry.owner_id,
                    alias: entry.alias.clone(),
                    start_time: entry.started_at,
                    end_time: Utc::now(),
                    duration_seconds: entry.duration.unwrap_or_default(),
                    credits_used: entry.charged_credits,
                });
                info!("CalculiX job {job_id} completed successfully");
            } else {
                entry.done = true;
                let message = format!("CalculiX exited with status: {}", status);
                entry.error = Some(message.clone());
                error!("CalculiX job {job_id} failed: {status}");
                if entry.charged_credits > CREDIT_BALANCE_EPSILON {
                    refund = Some((entry.owner_id, entry.charged_credits));
                    entry.charged_credits = 0.0;
                }
            }
        }

        Ok::<(Option<(i64, f64)>, Option<JobCompletionEmail>), anyhow::Error>((
            refund,
            completion_notification,
        ))
    }
    .await;

    let mut completion_notification = None;

    match execution {
        Ok((refund, notification)) => {
            completion_notification = notification;
            if let Some((user_id, amount)) = refund {
                if let Err(refund_err) = credit_user_credits(&state.db_pool, user_id, amount).await
                {
                    warn!(
                        "Failed to refund credits for job {} (user {}): {:?}",
                        job_id, user_id, refund_err
                    );
                } else {
                    info!(
                        "Refunded {:.3} credits to user {} after job {} failure",
                        amount, user_id, job_id
                    );
                }
            }
        }
        Err(err) => {
            error!("CalculiX job {job_id} failed to run: {err:?}");
            let mut jobs = state.jobs.write().await;
            let mut refund: Option<(i64, f64)> = None;
            if let Some(entry) = jobs.get_mut(&job_id) {
                entry.running = false;
                entry.done = true;
                entry.duration = Some(entry.started_instant.elapsed().as_secs_f64());
                entry.error = Some(err.to_string());
                entry.cancel_token = None;
                if entry.charged_credits > CREDIT_BALANCE_EPSILON {
                    refund = Some((entry.owner_id, entry.charged_credits));
                    entry.charged_credits = 0.0;
                }
            }
            drop(jobs);

            if let Some((user_id, amount)) = refund {
                if let Err(refund_err) = credit_user_credits(&state.db_pool, user_id, amount).await
                {
                    warn!(
                        "Failed to refund credits for job {} (user {}): {:?}",
                        job_id, user_id, refund_err
                    );
                } else {
                    info!(
                        "Refunded {:.3} credits to user {} after job {} execution failure",
                        amount, user_id, job_id
                    );
                }
            }
        }
    }

    if let Some(notification) = completion_notification {
        if let Err(err) = notify_job_completion(&state, notification).await {
            warn!(
                "Failed to send completion email for job {}: {}",
                job_id, err.message
            );
        }
    }
}

async fn status(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<JobSummary>>, AppError> {
    let jobs = state.jobs.read().await;
    let mut summaries: Vec<JobSummary> = jobs
        .values()
        .filter(|entry| auth.is_admin() || entry.owner_id == auth.user_id)
        .map(|entry| {
            let duration = if entry.running {
                entry.started_instant.elapsed().as_secs_f64()
            } else {
                entry.duration.unwrap_or_default()
            };

            JobSummary {
                id: entry.id,
                owner_id: entry.owner_id,
                alias: entry.alias.clone(),
                running: entry.running,
                done: entry.done,
                cancelled: entry.cancelled,
                start_time: entry.started_at,
                duration_seconds: duration,
                job_type: entry.job_type.clone(),
                error: entry.error.clone(),
                element_count: entry.element_count,
                estimated_runtime_seconds: entry.estimated_runtime_seconds,
                benchmark_score: entry.benchmark_score,
                estimated_credits: entry.estimated_credits,
                charged_credits: entry.charged_credits,
            }
        })
        .collect();

    summaries.sort_by_key(|summary| summary.start_time);
    summaries.reverse();

    Ok(Json(summaries))
}

async fn estimate_job_credits(
    AxumPath(job_id): AxumPath<Uuid>,
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<JobEstimateResponse>, AppError> {
    let job_entry = {
        let jobs = state.jobs.read().await;
        jobs.get(&job_id).cloned()
    }
    .ok_or_else(|| AppError::not_found("Job not found"))?;

    if !auth.is_admin() && job_entry.owner_id != auth.user_id {
        return Err(AppError::forbidden(
            "You are not allowed to inspect this job",
        ));
    }

    let mut estimate = JobCreditEstimate {
        estimated_credits: job_entry.estimated_credits,
        estimated_runtime_seconds: job_entry.estimated_runtime_seconds,
        element_count: job_entry.element_count,
        benchmark_score: job_entry.benchmark_score,
    };

    if estimate.element_count == 0 || !estimate.estimated_credits.is_finite() {
        let estimator = CreditEstimator::default();
        estimate = estimator.estimate_job_cost(&state, job_id).await?;
    }

    let charged_credits = if auth.is_admin() || auth.has_unlimited_credits() {
        0.0
    } else if estimate.estimated_credits.is_finite() {
        estimate.estimated_credits.max(0.0)
    } else {
        0.0
    };

    Ok(Json(JobEstimateResponse {
        job_id,
        estimated_credits: estimate.estimated_credits,
        estimated_runtime_seconds: estimate.estimated_runtime_seconds,
        element_count: estimate.element_count,
        benchmark_score: estimate.benchmark_score,
        charged_credits,
    }))
}

async fn estimate_job_upload_preview(
    State(state): State<AppState>,
    auth: AuthUser,
    mut multipart: Multipart,
) -> Result<Json<JobEstimatePreviewResponse>, AppError> {
    let mut buffer: Vec<u8> = Vec::new();
    let mut received_file = false;

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|err| AppError::internal(err.to_string()))?
    {
        let name = field.name().map(|name| name.to_string());
        match name.as_deref() {
            Some("alias") => {
                // Alias is optional for estimation; ignore value.
                let _ = field.text().await;
            }
            Some("file") | None => {
                received_file = true;
                while let Some(chunk) = field.chunk().await.map_err(|err| {
                    AppError::internal(format!("Failed to read upload chunk: {err}"))
                })? {
                    buffer.extend_from_slice(&chunk);
                }
            }
            Some(_) => {
                // Ignore any other fields.
            }
        }
    }

    if !received_file {
        return Err(AppError::bad_request(
            "Request must include a CalculiX .inp file for estimation",
        ));
    }

    if buffer.is_empty() {
        return Err(AppError::bad_request("Uploaded file is empty"));
    }

    let contents = String::from_utf8(buffer)
        .map_err(|_| AppError::bad_request("Input file must be UTF-8 encoded text"))?;

    let estimator = CreditEstimator::default();
    let estimate = estimator
        .estimate_from_contents(&state.db_pool, &contents)
        .await?;

    let estimated_credits = if estimate.estimated_credits.is_finite() {
        estimate.estimated_credits.max(0.0)
    } else {
        0.0
    };

    let charged_credits = if auth.is_admin() || auth.has_unlimited_credits() {
        0.0
    } else {
        estimated_credits
    };

    Ok(Json(JobEstimatePreviewResponse {
        estimated_credits,
        estimated_runtime_seconds: estimate.estimated_runtime_seconds,
        element_count: estimate.element_count,
        benchmark_score: estimate.benchmark_score,
        charged_credits,
    }))
}

async fn cancel_job(
    AxumPath(job_id): AxumPath<Uuid>,
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<StatusCode, AppError> {
    let cancel_token = {
        let mut jobs = state.jobs.write().await;
        let entry = jobs
            .get_mut(&job_id)
            .ok_or_else(|| AppError::not_found("Job not found"))?;

        if !auth.is_admin() && entry.owner_id != auth.user_id {
            return Err(AppError::forbidden(
                "You are not allowed to cancel this job",
            ));
        }

        if !entry.running {
            return Err(AppError::bad_request("Job is not currently running"));
        }

        entry
            .cancel_token
            .clone()
            .ok_or_else(|| AppError::internal("Cancellation handle missing for job"))?
    };

    cancel_token.cancel();
    Ok(StatusCode::ACCEPTED)
}

async fn delete_job(
    AxumPath(job_id): AxumPath<Uuid>,
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<StatusCode, AppError> {
    let job_dir = {
        let mut jobs = state.jobs.write().await;
        let entry = jobs
            .get(&job_id)
            .ok_or_else(|| AppError::not_found("Job not found"))?;

        if !auth.is_admin() && entry.owner_id != auth.user_id {
            return Err(AppError::forbidden(
                "You are not allowed to delete this job",
            ));
        }

        if entry.running {
            return Err(AppError::bad_request(
                "Cannot delete a job while it is still running",
            ));
        }

        let dir = entry.job_dir.clone();
        jobs.remove(&job_id);
        dir
    };

    match fs::remove_dir_all(&job_dir).await {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(AppError::internal(format!(
                "Failed to delete job directory: {err}"
            )))
        }
    }

    Ok(StatusCode::NO_CONTENT)
}

async fn download(
    AxumPath(job_id): AxumPath<Uuid>,
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Response, AppError> {
    let job = {
        let jobs = state.jobs.read().await;
        jobs.get(&job_id).cloned()
    };

    let job = job.ok_or_else(|| AppError::not_found("Job not found"))?;

    if !auth.is_admin() && job.owner_id != auth.user_id {
        return Err(AppError::forbidden(
            "You are not allowed to download this job",
        ));
    }

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

fn resolve_upload_limit_bytes() -> Result<usize> {
    const BYTES_PER_GIB: f64 = 1024f64 * 1024f64 * 1024f64;
    let raw_value = std::env::var("UPLOAD_LIMIT_GB").unwrap_or_else(|_| "1".to_string());
    let gigabytes: f64 = raw_value.trim().parse().with_context(|| {
        format!("Failed to parse UPLOAD_LIMIT_GB value '{raw_value}' as number")
    })?;

    if gigabytes <= 0.0 {
        return Err(anyhow!("UPLOAD_LIMIT_GB must be greater than zero"));
    }

    let bytes = gigabytes * BYTES_PER_GIB;
    if bytes > usize::MAX as f64 {
        return Err(anyhow!(
            "UPLOAD_LIMIT_GB value {gigabytes} GiB exceeds supported size on this platform"
        ));
    }

    Ok(bytes as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, extract::State, http::Request as HttpRequest, Json};
    use axum_extra::extract::cookie::CookieJar;
    use std::convert::Infallible;
    use tower::{service_fn, ServiceBuilder, ServiceExt};

    async fn setup_state() -> AppState {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("failed to create in-memory sqlite pool");

        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("failed to run migrations");

        let jobs_path = std::env::temp_dir().join(format!("calculix-tests-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&jobs_path).expect("failed to create temp jobs dir");

        let templates_path = jobs_path.join("templates/email");
        std::fs::create_dir_all(&templates_path).expect("failed to create temp templates dir");
        std::fs::write(
            templates_path.join("simulation_finished.html"),
            "<p>{{ alias }}</p>",
        )
        .expect("failed to write simulation template");
        std::fs::write(templates_path.join("test_email.html"), "<p>{{ alias }}</p>")
            .expect("failed to write test template");

        let email_templates =
            EmailTemplateEngine::new(&templates_path).expect("failed to initialise templates");

        let smtp_config_path = jobs_path.join("smtp.json");
        let mail_log_path = jobs_path.join("mail.log");

        let jwt_secret = b"test-secret";
        AppState {
            jobs: Arc::new(RwLock::new(HashMap::new())),
            jobs_dir: Arc::new(jobs_path),
            ccx_threads: 1,
            db_pool: pool,
            jwt_encoding_key: Arc::new(EncodingKey::from_secret(jwt_secret)),
            jwt_decoding_key: Arc::new(DecodingKey::from_secret(jwt_secret)),
            jwt_ttl_seconds: 3600,
            smtp_config_path: Arc::new(smtp_config_path),
            smtp_config: Arc::new(RwLock::new(None)),
            email_templates,
            mail_log_path: Arc::new(mail_log_path),
            mail_base_url: Arc::new(RwLock::new(None)),
        }
    }

    async fn insert_user(state: &AppState, email: &str, role: UserRole, active: bool) -> i64 {
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = Argon2::default()
            .hash_password("P@ssword123".as_bytes(), &salt)
            .expect("failed to hash password")
            .to_string();

        let result = query(
            "INSERT INTO users (email, password_hash, role, active, credits, unlimited) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(email)
        .bind(password_hash)
        .bind(role.as_str())
        .bind(active)
        .bind(DEFAULT_USER_CREDITS)
        .bind(0)
        .execute(&state.db_pool)
        .await
        .expect("failed to insert user");

        result.last_insert_rowid()
    }

    fn make_cookie_header(token: &str) -> String {
        format!("{AUTH_COOKIE}={token}")
    }

    async fn call_with_auth_layer(state: AppState, request: HttpRequest<Body>) -> Response {
        ServiceBuilder::new()
            .layer(from_fn_with_state(state, require_auth))
            .service(service_fn(|_req: HttpRequest<Body>| async {
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }))
            .oneshot(request)
            .await
            .expect("service invocation failed")
    }

    async fn call_with_admin_layer(state: AppState, request: HttpRequest<Body>) -> Response {
        ServiceBuilder::new()
            .layer(from_fn_with_state(state, require_admin))
            .service(service_fn(|_req: HttpRequest<Body>| async {
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }))
            .oneshot(request)
            .await
            .expect("service invocation failed")
    }

    #[tokio::test]
    async fn profile_requires_authentication_and_active_user() {
        let state = setup_state().await;
        let request = HttpRequest::builder()
            .uri("/api/profile")
            .body(Body::empty())
            .unwrap();

        let response = call_with_auth_layer(state.clone(), request).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let active_user_id = insert_user(&state, "active@example.com", UserRole::User, true).await;
        let (token, _) = create_jwt(&state, active_user_id, UserRole::User)
            .expect("failed to create token for active user");

        let request = HttpRequest::builder()
            .uri("/api/profile")
            .header(header::COOKIE, make_cookie_header(&token))
            .body(Body::empty())
            .unwrap();

        let response = call_with_auth_layer(state.clone(), request).await;

        assert_eq!(response.status(), StatusCode::OK);

        let inactive_user_id =
            insert_user(&state, "inactive@example.com", UserRole::User, false).await;
        let (token, _) = create_jwt(&state, inactive_user_id, UserRole::User)
            .expect("failed to create token for inactive user");

        let request = HttpRequest::builder()
            .uri("/api/profile")
            .header(header::COOKIE, make_cookie_header(&token))
            .body(Body::empty())
            .unwrap();

        let response = call_with_auth_layer(state, request).await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn register_rejected_when_signups_disabled() {
        let state = setup_state().await;
        insert_user(&state, "existing@example.com", UserRole::Admin, true).await;
        set_bool_setting(&state.db_pool, SETTING_ALLOW_SIGNUPS, false)
            .await
            .expect("failed to disable signups");

        let payload = RegisterPayload {
            email: "new@example.com".to_string(),
            password: "StrongPass1!".to_string(),
        };

        let result = register(State(state.clone()), CookieJar::new(), Json(payload)).await;

        match result {
            Ok(_) => panic!("registration succeeded despite being disabled"),
            Err(err) => {
                assert_eq!(err.status, StatusCode::FORBIDDEN);
                assert!(
                    err.message.to_lowercase().contains("disabled"),
                    "unexpected message: {}",
                    err.message
                );
            }
        }
    }

    #[tokio::test]
    async fn admin_routes_reject_non_admin_users() {
        let state = setup_state().await;
        let user_id = insert_user(&state, "user@example.com", UserRole::User, true).await;
        let admin_id = insert_user(&state, "admin@example.com", UserRole::Admin, true).await;

        let (user_token, _) =
            create_jwt(&state, user_id, UserRole::User).expect("failed to create user token");
        let (admin_token, _) =
            create_jwt(&state, admin_id, UserRole::Admin).expect("failed to create admin token");

        let request = HttpRequest::builder()
            .uri("/api/admin/users")
            .header(header::COOKIE, make_cookie_header(&user_token))
            .body(Body::empty())
            .unwrap();

        let response = call_with_admin_layer(state.clone(), request).await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let request = HttpRequest::builder()
            .uri("/api/admin/users")
            .header(header::COOKIE, make_cookie_header(&admin_token))
            .body(Body::empty())
            .unwrap();

        let response = call_with_admin_layer(state, request).await;

        assert_eq!(response.status(), StatusCode::OK);
    }
}
