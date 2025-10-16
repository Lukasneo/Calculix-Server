use std::{
    collections::HashMap,
    env,
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
    body::Bytes,
    extract::{FromRef, FromRequestParts, Multipart, Path as AxumPath, State},
    http::{header, request::Parts, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post},
    Json, Router,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use chrono::{DateTime, Duration, TimeZone, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use password_hash::SaltString;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sqlx::{
    query, query_as,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    FromRow, SqlitePool,
};
use std::str::FromStr;
use time::OffsetDateTime;
use tokio::{fs, io::AsyncWriteExt, net::TcpListener, process::Command, sync::RwLock};
use tokio_util::sync::CancellationToken;
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
    db_pool: SqlitePool,
    jwt_encoding_key: Arc<EncodingKey>,
    jwt_decoding_key: Arc<DecodingKey>,
    jwt_ttl_seconds: i64,
}

#[derive(Clone)]
struct JobEntry {
    id: Uuid,
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
}

#[derive(Serialize)]
struct JobSummary {
    id: Uuid,
    alias: String,
    running: bool,
    done: bool,
    cancelled: bool,
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

    fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, message)
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, message)
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
    created_at: i64,
}

#[derive(Serialize)]
struct UserResponse {
    id: i64,
    email: String,
    role: UserRole,
    created_at: String,
}

impl UserRecord {
    fn into_response(self) -> Result<UserResponse, AppError> {
        let role = UserRole::from_db(&self.role)?;
        Ok(UserResponse {
            id: self.id,
            email: self.email,
            role,
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
struct SimulationCreatePayload {
    alias: Option<String>,
}

#[derive(Deserialize)]
struct SimulationUpdatePayload {
    alias: Option<String>,
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
}

impl AuthUser {
    fn is_admin(&self) -> bool {
        self.role.is_admin()
    }
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
        let jar = CookieJar::from_request_parts(parts, state)
            .await
            .map_err(|_| AppError::unauthorized("Failed to read authentication cookie"))?;

        let cookie = jar
            .get(AUTH_COOKIE)
            .ok_or_else(|| AppError::unauthorized("Authentication required"))?;

        let app_state = AppState::from_ref(state);

        let token = cookie.value();
        let token_data = decode::<AuthClaims>(
            token,
            app_state.jwt_decoding_key.as_ref(),
            &Validation::default(),
        )
        .map_err(|_| AppError::unauthorized("Invalid or expired authentication token"))?;

        let role = UserRole::from_db(&token_data.claims.role)?;

        Ok(AuthUser {
            user_id: token_data.claims.sub,
            role,
        })
    }
}

async fn fetch_user_by_email(
    pool: &SqlitePool,
    email: &str,
) -> Result<Option<UserRecord>, AppError> {
    query_as::<_, UserRecord>(
        "SELECT id, email, password_hash, role, created_at FROM users WHERE email = ?",
    )
    .bind(email)
    .fetch_optional(pool)
    .await
    .map_err(|err| AppError::internal(format!("Failed to load user by email: {err}")))
}

async fn fetch_user_by_id(pool: &SqlitePool, user_id: i64) -> Result<UserRecord, AppError> {
    query_as::<_, UserRecord>(
        "SELECT id, email, password_hash, role, created_at FROM users WHERE id = ?",
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

    query("INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)")
        .bind(&normalized_email)
        .bind(password_hash)
        .bind(ROLE_ADMIN)
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
    };

    let upload_router = Router::new()
        .route("/upload", post(upload))
        .route("/status", get(status))
        .route("/download/:id", get(download))
        .route("/jobs/:id/cancel", post(cancel_job))
        .route("/jobs/:id", delete(delete_job))
        .layer(DefaultBodyLimit::max(max_upload_bytes));

    let api_router = Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/me", get(me))
        .route(
            "/simulations",
            get(list_simulations).post(create_simulation),
        )
        .route(
            "/simulations/:id",
            patch(update_simulation).delete(delete_simulation),
        );

    let static_service = ServeDir::new(frontend_dir.clone())
        .not_found_service(ServeFile::new(frontend_dir.join("index.html")));

    let app = Router::new()
        .merge(upload_router)
        .merge(api_router)
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

    let result = query("INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)")
        .bind(&email)
        .bind(&password_hash)
        .bind(target_role.as_str())
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

    let user_record = fetch_user_by_email(&state.db_pool, &email)
        .await?
        .ok_or_else(|| AppError::unauthorized("Invalid email or password"))?;

    let parsed_hash = PasswordHash::new(&user_record.password_hash)
        .map_err(|err| AppError::internal(format!("Invalid stored password hash: {err}")))?;

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .map_err(|_| AppError::unauthorized("Invalid email or password"))?;

    let role = UserRole::from_db(&user_record.role)?;
    let (token, expires) = create_jwt(&state, user_record.id, role)?;
    let cookie = build_auth_cookie(token, expires);
    let jar = jar.add(cookie);

    let user_response = user_record.into_response()?;
    Ok((jar, Json(user_response)))
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

async fn upload(
    State(state): State<AppState>,
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

                return process_inp_upload(file_field, state, alias).await;
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

async fn process_inp_upload(
    mut field: Field<'_>,
    state: AppState,
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

    let detected_job_type = detect_job_type(&model_path).await.unwrap_or(None);

    let cancel_token = CancellationToken::new();

    let job_entry = JobEntry {
        id: job_id,
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
                info!("CalculiX job {job_id} completed successfully");
            } else {
                entry.done = true;
                let message = format!("CalculiX exited with status: {}", status);
                entry.error = Some(message.clone());
                error!("CalculiX job {job_id} failed: {status}");
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
            entry.cancel_token = None;
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
                alias: entry.alias.clone(),
                running: entry.running,
                done: entry.done,
                cancelled: entry.cancelled,
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

async fn cancel_job(
    AxumPath(job_id): AxumPath<Uuid>,
    State(state): State<AppState>,
) -> Result<StatusCode, AppError> {
    let cancel_token = {
        let mut jobs = state.jobs.write().await;
        let entry = jobs
            .get_mut(&job_id)
            .ok_or_else(|| AppError::not_found("Job not found"))?;

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
) -> Result<StatusCode, AppError> {
    let job_dir = {
        let mut jobs = state.jobs.write().await;
        let entry = jobs
            .get(&job_id)
            .ok_or_else(|| AppError::not_found("Job not found"))?;

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
