#![forbid(unsafe_code)]

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use messenger_crypto_core::{KeyPackageBinding, RegistrationProof};
use messenger_key_directory::{InMemoryKeyDirectory, KeyDirectoryError, PublishedKeyPackage};
use messenger_registration::{InMemoryRegistrationService, RegistrationError};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const MAX_KEY_PACKAGE_BYTES: usize = 64 * 1024;
const MAX_ACCOUNT_ID_CHARS: usize = 64;

#[derive(Clone)]
struct AppState {
    registration: Arc<InMemoryRegistrationService>,
    key_directory: Arc<InMemoryKeyDirectory>,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistrationChallengeResponse {
    pub challenge_id: Uuid,
    pub challenge: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistrationRequest {
    pub challenge_id: Uuid,
    pub proof: RegistrationProof,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistrationResponse {
    pub account_id: String,
    pub root_public_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyPackageUploadRequest {
    pub key_package: String,
    pub binding: KeyPackageBinding,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyPackageClaimRequest {
    pub account_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyPackageResponse {
    pub key_package: String,
    pub binding: KeyPackageBinding,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: &'static str,
}

enum ApiError {
    InvalidRequest,
    RegistrationFailed,
    AccountConflict,
    KeyPackageRejected,
    KeyPackageConflict,
    KeyPackageUnavailable,
    ServiceUnavailable,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::InvalidRequest => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::RegistrationFailed => (StatusCode::UNAUTHORIZED, "registration_failed"),
            Self::AccountConflict => (StatusCode::CONFLICT, "account_conflict"),
            Self::KeyPackageRejected => (StatusCode::UNAUTHORIZED, "key_package_rejected"),
            Self::KeyPackageConflict => (StatusCode::CONFLICT, "key_package_conflict"),
            Self::KeyPackageUnavailable => (StatusCode::NOT_FOUND, "key_package_unavailable"),
            Self::ServiceUnavailable => (StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
        };

        (status, Json(ErrorResponse { error: code })).into_response()
    }
}

pub fn app() -> Router {
    let state = AppState {
        registration: Arc::new(InMemoryRegistrationService::default()),
        key_directory: Arc::new(InMemoryKeyDirectory::default()),
    };

    Router::new()
        .route("/health", get(health))
        .route(
            "/v1/registration/challenge",
            post(issue_registration_challenge),
        )
        .route("/v1/registration", post(register_account))
        .route("/v1/key-packages", post(upload_key_package))
        .route("/v1/key-packages/claim", post(claim_key_package))
        .with_state(state)
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn issue_registration_challenge(
    State(state): State<AppState>,
) -> Result<(StatusCode, Json<RegistrationChallengeResponse>), ApiError> {
    let challenge = state
        .registration
        .issue_challenge()
        .map_err(map_registration_error)?;

    Ok((
        StatusCode::CREATED,
        Json(RegistrationChallengeResponse {
            challenge_id: challenge.id,
            challenge: URL_SAFE_NO_PAD.encode(challenge.bytes),
        }),
    ))
}

async fn register_account(
    State(state): State<AppState>,
    Json(request): Json<RegistrationRequest>,
) -> Result<(StatusCode, Json<RegistrationResponse>), ApiError> {
    let account = state
        .registration
        .register(request.challenge_id, request.proof)
        .map_err(map_registration_error)?;

    Ok((
        StatusCode::CREATED,
        Json(RegistrationResponse {
            account_id: account.account_id,
            root_public_key: account.root_public_key,
        }),
    ))
}

async fn upload_key_package(
    State(state): State<AppState>,
    Json(request): Json<KeyPackageUploadRequest>,
) -> Result<StatusCode, ApiError> {
    let key_package = decode_key_package(&request.key_package)?;
    let account = state
        .registration
        .account(&request.binding.account_id)
        .ok_or(ApiError::KeyPackageRejected)?;

    state
        .key_directory
        .upload(
            &account,
            PublishedKeyPackage {
                key_package,
                binding: request.binding,
            },
        )
        .map_err(map_key_directory_error)?;

    Ok(StatusCode::CREATED)
}

async fn claim_key_package(
    State(state): State<AppState>,
    Json(request): Json<KeyPackageClaimRequest>,
) -> Result<Json<KeyPackageResponse>, ApiError> {
    if request.account_id.is_empty() || request.account_id.len() > MAX_ACCOUNT_ID_CHARS {
        return Err(ApiError::InvalidRequest);
    }

    let package = state
        .key_directory
        .claim(&request.account_id)
        .map_err(map_key_directory_error)?;

    Ok(Json(KeyPackageResponse {
        key_package: URL_SAFE_NO_PAD.encode(package.key_package),
        binding: package.binding,
    }))
}

fn decode_key_package(encoded: &str) -> Result<Vec<u8>, ApiError> {
    let key_package = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ApiError::InvalidRequest)?;
    if key_package.is_empty() || key_package.len() > MAX_KEY_PACKAGE_BYTES {
        return Err(ApiError::InvalidRequest);
    }
    Ok(key_package)
}

fn map_registration_error(error: RegistrationError) -> ApiError {
    match error {
        RegistrationError::UnknownChallenge
        | RegistrationError::ExpiredChallenge
        | RegistrationError::InvalidProof => ApiError::RegistrationFailed,
        RegistrationError::AccountConflict => ApiError::AccountConflict,
        RegistrationError::EntropyUnavailable | RegistrationError::InvalidChallengeLifetime => {
            ApiError::ServiceUnavailable
        }
    }
}

fn map_key_directory_error(error: KeyDirectoryError) -> ApiError {
    match error {
        KeyDirectoryError::InvalidBinding | KeyDirectoryError::AccountMismatch => {
            ApiError::KeyPackageRejected
        }
        KeyDirectoryError::DuplicateKeyPackage => ApiError::KeyPackageConflict,
        KeyDirectoryError::NoKeyPackage => ApiError::KeyPackageUnavailable,
    }
}
