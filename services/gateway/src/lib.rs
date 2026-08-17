#![forbid(unsafe_code)]

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::{
        HeaderMap, StatusCode,
        header::AUTHORIZATION,
    },
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use messenger_crypto_core::{
    DeviceAuthProof, DeviceCertificate, KeyPackageBinding, RegistrationProof,
};
use messenger_device_service::{DeviceServiceError, InMemoryDeviceService, RegisteredDevice};
use messenger_key_directory::{InMemoryKeyDirectory, KeyDirectoryError, PublishedKeyPackage};
use messenger_protocol::{ENVELOPE_VERSION, Envelope};
use messenger_registration::{InMemoryRegistrationService, RegistrationError};
use messenger_relay::{InMemoryRelay, RelayError};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const MAX_KEY_PACKAGE_BYTES: usize = 64 * 1024;
const MAX_ACCOUNT_ID_CHARS: usize = 64;
const MAX_DEVICE_ID_CHARS: usize = 64;
const MAX_MAILBOX_ID_CHARS: usize = 64;
const MAX_ENVELOPE_CIPHERTEXT_BYTES: usize = 256 * 1024;
const MAX_ACK_IDS: usize = 1024;
const SESSION_TOKEN_BYTES: usize = 32;

#[derive(Clone)]
struct AppState {
    registration: Arc<InMemoryRegistrationService>,
    devices: Arc<InMemoryDeviceService>,
    key_directory: Arc<InMemoryKeyDirectory>,
    relay: Arc<InMemoryRelay>,
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
pub struct DeviceRegistrationRequest {
    pub certificate: DeviceCertificate,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceAuthChallengeRequest {
    pub device_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceAuthChallengeResponse {
    pub challenge_id: Uuid,
    pub challenge: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceSessionRequest {
    pub challenge_id: Uuid,
    pub proof: DeviceAuthProof,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceSessionResponse {
    pub token: String,
    pub expires_in_seconds: u64,
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
    pub device_certificate: DeviceCertificate,
}

/// Anonymous sender-to-mailbox transport DTO. There is deliberately no sender
/// account or device identifier in this structure.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnvelopeSubmitRequest {
    pub version: u8,
    pub envelope_id: Uuid,
    pub mailbox_id: String,
    pub ciphertext: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailboxEnvelopeResponse {
    pub version: u8,
    pub envelope_id: Uuid,
    pub ciphertext: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailboxResponse {
    pub envelopes: Vec<MailboxEnvelopeResponse>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailboxAckRequest {
    pub envelope_ids: Vec<Uuid>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailboxAckResponse {
    pub acknowledged: usize,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: &'static str,
}

enum ApiError {
    InvalidRequest,
    PayloadTooLarge,
    RegistrationFailed,
    AccountConflict,
    DeviceRegistrationFailed,
    DeviceConflict,
    DeviceAuthFailed,
    KeyPackageRejected,
    KeyPackageConflict,
    KeyPackageUnavailable,
    ServiceUnavailable,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::InvalidRequest => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::PayloadTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"),
            Self::RegistrationFailed => (StatusCode::UNAUTHORIZED, "registration_failed"),
            Self::AccountConflict => (StatusCode::CONFLICT, "account_conflict"),
            Self::DeviceRegistrationFailed => {
                (StatusCode::UNAUTHORIZED, "device_registration_failed")
            }
            Self::DeviceConflict => (StatusCode::CONFLICT, "device_conflict"),
            Self::DeviceAuthFailed => (StatusCode::UNAUTHORIZED, "device_auth_failed"),
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
        devices: Arc::new(InMemoryDeviceService::default()),
        key_directory: Arc::new(InMemoryKeyDirectory::default()),
        relay: Arc::new(InMemoryRelay::default()),
    };

    Router::new()
        .route("/health", get(health))
        .route(
            "/v1/registration/challenge",
            post(issue_registration_challenge),
        )
        .route("/v1/registration", post(register_account))
        .route("/v1/devices", post(register_device))
        .route("/v1/device-auth/challenge", post(issue_device_challenge))
        .route("/v1/device-auth/session", post(create_device_session))
        .route("/v1/key-packages", post(upload_key_package))
        .route("/v1/key-packages/claim", post(claim_key_package))
        .route("/v1/envelopes", post(submit_envelope))
        .route("/v1/mailbox", get(retrieve_mailbox))
        .route("/v1/mailbox/ack", post(acknowledge_mailbox))
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

async fn register_device(
    State(state): State<AppState>,
    Json(request): Json<DeviceRegistrationRequest>,
) -> Result<StatusCode, ApiError> {
    let account = state
        .registration
        .account(&request.certificate.account_id)
        .ok_or(ApiError::DeviceRegistrationFailed)?;
    state
        .devices
        .register_device(&account, request.certificate)
        .map_err(map_device_registration_error)?;
    Ok(StatusCode::CREATED)
}

async fn issue_device_challenge(
    State(state): State<AppState>,
    Json(request): Json<DeviceAuthChallengeRequest>,
) -> Result<(StatusCode, Json<DeviceAuthChallengeResponse>), ApiError> {
    if request.device_id.is_empty() || request.device_id.len() > MAX_DEVICE_ID_CHARS {
        return Err(ApiError::InvalidRequest);
    }
    let challenge = state
        .devices
        .issue_challenge(&request.device_id)
        .map_err(map_device_auth_error)?;

    Ok((
        StatusCode::CREATED,
        Json(DeviceAuthChallengeResponse {
            challenge_id: challenge.id,
            challenge: URL_SAFE_NO_PAD.encode(challenge.bytes),
        }),
    ))
}

async fn create_device_session(
    State(state): State<AppState>,
    Json(request): Json<DeviceSessionRequest>,
) -> Result<(StatusCode, Json<DeviceSessionResponse>), ApiError> {
    let session = state
        .devices
        .authenticate(request.challenge_id, request.proof)
        .map_err(map_device_auth_error)?;

    Ok((
        StatusCode::CREATED,
        Json(DeviceSessionResponse {
            token: URL_SAFE_NO_PAD.encode(session.token),
            expires_in_seconds: session.expires_in.as_secs(),
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
    let device = state
        .devices
        .device(&request.binding.device_id)
        .ok_or(ApiError::KeyPackageRejected)?;

    if device.certificate.account_id != account.account_id
        || device.certificate.root_public_key != account.root_public_key
        || device.certificate.device_id != request.binding.device_id
    {
        return Err(ApiError::KeyPackageRejected);
    }

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
    let device = state
        .devices
        .device(&package.binding.device_id)
        .ok_or(ApiError::KeyPackageUnavailable)?;

    if device.certificate.account_id != package.binding.account_id
        || device.certificate.root_public_key != package.binding.root_public_key
    {
        return Err(ApiError::KeyPackageRejected);
    }

    Ok(Json(KeyPackageResponse {
        key_package: URL_SAFE_NO_PAD.encode(package.key_package),
        binding: package.binding,
        device_certificate: device.certificate,
    }))
}

async fn submit_envelope(
    State(state): State<AppState>,
    Json(request): Json<EnvelopeSubmitRequest>,
) -> Result<StatusCode, ApiError> {
    if request.version != ENVELOPE_VERSION
        || request.mailbox_id.is_empty()
        || request.mailbox_id.len() > MAX_MAILBOX_ID_CHARS
    {
        return Err(ApiError::InvalidRequest);
    }
    let ciphertext = decode_ciphertext(&request.ciphertext)?;

    // Deliberately do not reveal whether a mailbox exists. An unknown or revoked
    // destination is accepted and dropped, preventing mailbox enumeration.
    if state.devices.device_by_mailbox(&request.mailbox_id).is_none() {
        return Ok(StatusCode::ACCEPTED);
    }

    let envelope = Envelope {
        version: request.version,
        envelope_id: request.envelope_id,
        mailbox_id: request.mailbox_id,
        ciphertext,
    };
    match state.relay.enqueue(envelope) {
        Ok(()) | Err(RelayError::DuplicateEnvelope(_)) => Ok(StatusCode::ACCEPTED),
    }
}

async fn retrieve_mailbox(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<MailboxResponse>, ApiError> {
    let device = authorize_bearer(&state, &headers)?;
    let envelopes = state
        .relay
        .retrieve_mailbox(&device.certificate.mailbox_id)
        .into_iter()
        .map(|envelope| MailboxEnvelopeResponse {
            version: envelope.version,
            envelope_id: envelope.envelope_id,
            ciphertext: URL_SAFE_NO_PAD.encode(envelope.ciphertext),
        })
        .collect();

    Ok(Json(MailboxResponse { envelopes }))
}

async fn acknowledge_mailbox(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<MailboxAckRequest>,
) -> Result<Json<MailboxAckResponse>, ApiError> {
    if request.envelope_ids.len() > MAX_ACK_IDS {
        return Err(ApiError::InvalidRequest);
    }
    let device = authorize_bearer(&state, &headers)?;
    let acknowledged = state
        .relay
        .acknowledge(&device.certificate.mailbox_id, &request.envelope_ids);

    Ok(Json(MailboxAckResponse { acknowledged }))
}

fn authorize_bearer(state: &AppState, headers: &HeaderMap) -> Result<RegisteredDevice, ApiError> {
    let value = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(ApiError::DeviceAuthFailed)?;
    let (scheme, encoded_token) = value.split_once(' ').ok_or(ApiError::DeviceAuthFailed)?;
    if !scheme.eq_ignore_ascii_case("Bearer")
        || encoded_token.is_empty()
        || encoded_token.contains(char::is_whitespace)
    {
        return Err(ApiError::DeviceAuthFailed);
    }

    let decoded = URL_SAFE_NO_PAD
        .decode(encoded_token)
        .map_err(|_| ApiError::DeviceAuthFailed)?;
    let token: [u8; SESSION_TOKEN_BYTES] = decoded
        .try_into()
        .map_err(|_| ApiError::DeviceAuthFailed)?;
    state
        .devices
        .authorize_session(&token)
        .map_err(|_| ApiError::DeviceAuthFailed)
}

fn decode_key_package(encoded: &str) -> Result<Vec<u8>, ApiError> {
    let key_package = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ApiError::InvalidRequest)?;
    if key_package.is_empty() {
        return Err(ApiError::InvalidRequest);
    }
    if key_package.len() > MAX_KEY_PACKAGE_BYTES {
        return Err(ApiError::PayloadTooLarge);
    }
    Ok(key_package)
}

fn decode_ciphertext(encoded: &str) -> Result<Vec<u8>, ApiError> {
    let ciphertext = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ApiError::InvalidRequest)?;
    if ciphertext.is_empty() {
        return Err(ApiError::InvalidRequest);
    }
    if ciphertext.len() > MAX_ENVELOPE_CIPHERTEXT_BYTES {
        return Err(ApiError::PayloadTooLarge);
    }
    Ok(ciphertext)
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

fn map_device_registration_error(error: DeviceServiceError) -> ApiError {
    match error {
        DeviceServiceError::InvalidCertificate
        | DeviceServiceError::AccountMismatch
        | DeviceServiceError::DeviceRevoked
        | DeviceServiceError::UnknownDevice
        | DeviceServiceError::UnknownChallenge
        | DeviceServiceError::ExpiredChallenge
        | DeviceServiceError::InvalidProof
        | DeviceServiceError::InvalidSession
        | DeviceServiceError::ExpiredSession => ApiError::DeviceRegistrationFailed,
        DeviceServiceError::DeviceConflict | DeviceServiceError::MailboxConflict => {
            ApiError::DeviceConflict
        }
        DeviceServiceError::EntropyUnavailable | DeviceServiceError::InvalidLifetime => {
            ApiError::ServiceUnavailable
        }
    }
}

fn map_device_auth_error(error: DeviceServiceError) -> ApiError {
    match error {
        DeviceServiceError::UnknownDevice
        | DeviceServiceError::DeviceRevoked
        | DeviceServiceError::UnknownChallenge
        | DeviceServiceError::ExpiredChallenge
        | DeviceServiceError::InvalidProof
        | DeviceServiceError::InvalidSession
        | DeviceServiceError::ExpiredSession
        | DeviceServiceError::InvalidCertificate
        | DeviceServiceError::AccountMismatch => ApiError::DeviceAuthFailed,
        DeviceServiceError::DeviceConflict | DeviceServiceError::MailboxConflict => {
            ApiError::DeviceAuthFailed
        }
        DeviceServiceError::EntropyUnavailable | DeviceServiceError::InvalidLifetime => {
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
