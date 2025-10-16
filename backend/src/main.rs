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
const SETTING_ALLOW_SIGNUPS: &str = "allow_signups";

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
    created_at: i64,
}

#[derive(Serialize)]
struct UserResponse {
    id: i64,
    email: String,
    role: UserRole,
    active: bool,
    created_at: String,
}

#[derive(Serialize)]
struct ProfileResponse {
    id: i64,
    email: String,
    role: UserRole,
    active: bool,
}

#[derive(Serialize)]
struct AdminUserResponse {
    id: i64,
    email: String,
    role: UserRole,
    active: bool,
    created_at: String,
}

#[derive(Serialize)]
struct SettingsResponse {
    allow_signups: bool,
}

#[derive(Deserialize)]
struct UpdateSettingsPayload {
    allow_signups: bool,
}

impl UserRecord {
    fn into_response(self) -> Result<UserResponse, AppError> {
        let role = UserRole::from_db(&self.role)?;
        Ok(UserResponse {
            id: self.id,
            email: self.email,
            role,
            active: self.active,
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
        })
    }

    fn into_admin_response(self) -> Result<AdminUserResponse, AppError> {
        let role = UserRole::from_db(&self.role)?;
        Ok(AdminUserResponse {
            id: self.id,
            email: self.email,
            role,
            active: self.active,
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

        let app_state = AppState::from_ref(state);
        let user_record = fetch_user_by_id(&app_state.db_pool, token_data.claims.sub).await?;
        if !user_record.active {
            return Err(AppError::forbidden("Account deactivated"));
        }

        let role = UserRole::from_db(&user_record.role)?;

        Ok(AuthUser {
            user_id: user_record.id,
            role,
        })
    }
}

async fn fetch_user_by_email(
    pool: &SqlitePool,
    email: &str,
) -> Result<Option<UserRecord>, AppError> {
    query_as::<_, UserRecord>(
        "SELECT id, email, password_hash, role, active, created_at FROM users WHERE email = ?",
    )
    .bind(email)
    .fetch_optional(pool)
    .await
    .map_err(|err| AppError::internal(format!("Failed to load user by email: {err}")))
}

async fn fetch_user_by_id(pool: &SqlitePool, user_id: i64) -> Result<UserRecord, AppError> {
    query_as::<_, UserRecord>(
        "SELECT id, email, password_hash, role, active, created_at FROM users WHERE id = ?",
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
    ensure_setting(pool, SETTING_ALLOW_SIGNUPS, "true").await
}

fn core_api_router() -> Router<AppState> {
    Router::new()
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
        )
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

    ensure_default_settings(&db_pool)
        .await
        .context("Failed to ensure default application settings")?;

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

    let profile_router = Router::new()
        .route("/", get(profile))
        .route("/update_email", post(update_profile_email))
        .route("/update_password", post(update_profile_password))
        .route_layer(from_fn_with_state(state.clone(), require_auth));

    let admin_router = Router::new()
        .route("/users", get(admin_list_users))
        .route("/users/:id/toggle_active", post(admin_toggle_user_active))
        .route("/users/:id", delete(admin_delete_user))
        .nest(
            "/settings",
            Router::new().route("/", get(admin_get_settings).post(admin_update_settings)),
        )
        .route_layer(from_fn_with_state(state.clone(), require_admin));

    let public_settings_router = Router::new().route("/", get(public_settings));

    let api_router = core_api_router()
        .nest("/profile", profile_router)
        .nest("/admin", admin_router)
        .nest("/settings", public_settings_router);

    let legacy_router = core_api_router();

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

    if !user_record.active {
        return Err(AppError::forbidden("Account deactivated"));
    }

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
        "SELECT id, email, password_hash, role, active, created_at FROM users ORDER BY created_at DESC",
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
    Ok(SettingsResponse { allow_signups })
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
    set_bool_setting(&state.db_pool, SETTING_ALLOW_SIGNUPS, payload.allow_signups).await?;
    Ok(Json(load_settings(&state.db_pool).await?))
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

        let jwt_secret = b"test-secret";
        AppState {
            jobs: Arc::new(RwLock::new(HashMap::new())),
            jobs_dir: Arc::new(jobs_path),
            ccx_threads: 1,
            db_pool: pool,
            jwt_encoding_key: Arc::new(EncodingKey::from_secret(jwt_secret)),
            jwt_decoding_key: Arc::new(DecodingKey::from_secret(jwt_secret)),
            jwt_ttl_seconds: 3600,
        }
    }

    async fn insert_user(state: &AppState, email: &str, role: UserRole, active: bool) -> i64 {
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = Argon2::default()
            .hash_password("P@ssword123".as_bytes(), &salt)
            .expect("failed to hash password")
            .to_string();

        let result =
            query("INSERT INTO users (email, password_hash, role, active) VALUES (?, ?, ?, ?)")
                .bind(email)
                .bind(password_hash)
                .bind(role.as_str())
                .bind(active)
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
