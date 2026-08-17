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
use messenger_crypto_core::RegistrationProof;
use messenger_registration::{InMemoryRegistrationService, RegistrationError};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    registration: Arc<InMemoryRegistrationService>,
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

#[derive(Serialize)]
struct ErrorResponse {
    error: &'static str,
}

enum ApiError {
    RegistrationFailed,
    AccountConflict,
    ServiceUnavailable,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::RegistrationFailed => (StatusCode::UNAUTHORIZED, "registration_failed"),
            Self::AccountConflict => (StatusCode::CONFLICT, "account_conflict"),
            Self::ServiceUnavailable => (StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
        };

        (status, Json(ErrorResponse { error: code })).into_response()
    }
}

pub fn app() -> Router {
    let state = AppState {
        registration: Arc::new(InMemoryRegistrationService::default()),
    };

    Router::new()
        .route("/health", get(health))
        .route(
            "/v1/registration/challenge",
            post(issue_registration_challenge),
        )
        .route("/v1/registration", post(register_account))
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
