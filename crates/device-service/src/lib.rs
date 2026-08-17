#![forbid(unsafe_code)]

use std::{
    collections::{HashMap, HashSet},
    sync::{Mutex, MutexGuard},
    time::{Duration, Instant},
};

use messenger_crypto_core::{DeviceAuthProof, DeviceCertificate};
use messenger_registration::RegisteredAccount;
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

const AUTH_CHALLENGE_BYTES: usize = 32;
const SESSION_TOKEN_BYTES: usize = 32;
const DEFAULT_AUTH_CHALLENGE_TTL: Duration = Duration::from_secs(120);
const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(900);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredDevice {
    pub certificate: DeviceCertificate,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceAuthChallenge {
    pub id: Uuid,
    pub bytes: [u8; AUTH_CHALLENGE_BYTES],
    pub device_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuedDeviceSession {
    pub token: [u8; SESSION_TOKEN_BYTES],
    pub expires_in: Duration,
}

pub struct InMemoryDeviceService {
    challenge_ttl: Duration,
    session_ttl: Duration,
    state: Mutex<DeviceServiceState>,
}

#[derive(Default)]
struct DeviceServiceState {
    devices: HashMap<String, RegisteredDevice>,
    mailbox_to_device: HashMap<String, String>,
    revoked_device_ids: HashSet<String>,
    challenges: HashMap<Uuid, ChallengeRecord>,
    sessions: HashMap<[u8; 32], SessionRecord>,
}

struct ChallengeRecord {
    bytes: [u8; AUTH_CHALLENGE_BYTES],
    device_id: String,
    expires_at: Instant,
}

#[derive(Clone)]
struct SessionRecord {
    device_id: String,
    expires_at: Instant,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum DeviceServiceError {
    #[error("device certificate is invalid")]
    InvalidCertificate,
    #[error("device certificate does not match the registered account")]
    AccountMismatch,
    #[error("device identifier conflicts with another certificate")]
    DeviceConflict,
    #[error("mailbox identifier is already assigned")]
    MailboxConflict,
    #[error("device has been revoked")]
    DeviceRevoked,
    #[error("device is not registered")]
    UnknownDevice,
    #[error("operating-system entropy source unavailable")]
    EntropyUnavailable,
    #[error("challenge/session lifetime is invalid")]
    InvalidLifetime,
    #[error("device-auth challenge is unknown or already consumed")]
    UnknownChallenge,
    #[error("device-auth challenge expired")]
    ExpiredChallenge,
    #[error("device-auth proof is invalid")]
    InvalidProof,
    #[error("device session is invalid")]
    InvalidSession,
    #[error("device session expired")]
    ExpiredSession,
}

impl Default for InMemoryDeviceService {
    fn default() -> Self {
        Self::new(DEFAULT_AUTH_CHALLENGE_TTL, DEFAULT_SESSION_TTL)
    }
}

impl InMemoryDeviceService {
    pub fn new(challenge_ttl: Duration, session_ttl: Duration) -> Self {
        Self {
            challenge_ttl,
            session_ttl,
            state: Mutex::new(DeviceServiceState::default()),
        }
    }

    pub fn register_device(
        &self,
        account: &RegisteredAccount,
        certificate: DeviceCertificate,
    ) -> Result<RegisteredDevice, DeviceServiceError> {
        certificate
            .verify()
            .map_err(|_| DeviceServiceError::InvalidCertificate)?;
        if certificate.account_id != account.account_id
            || certificate.root_public_key != account.root_public_key
        {
            return Err(DeviceServiceError::AccountMismatch);
        }

        let mut state = self.state();
        if state.revoked_device_ids.contains(&certificate.device_id) {
            return Err(DeviceServiceError::DeviceRevoked);
        }

        if let Some(existing) = state.devices.get(&certificate.device_id) {
            if existing.certificate == certificate {
                return Ok(existing.clone());
            }
            return Err(DeviceServiceError::DeviceConflict);
        }

        if let Some(existing_device_id) = state.mailbox_to_device.get(&certificate.mailbox_id) {
            if existing_device_id != &certificate.device_id {
                return Err(DeviceServiceError::MailboxConflict);
            }
        }

        let registered = RegisteredDevice {
            certificate: certificate.clone(),
        };
        state
            .mailbox_to_device
            .insert(certificate.mailbox_id.clone(), certificate.device_id.clone());
        state
            .devices
            .insert(certificate.device_id.clone(), registered.clone());
        Ok(registered)
    }

    pub fn issue_challenge(
        &self,
        device_id: &str,
    ) -> Result<DeviceAuthChallenge, DeviceServiceError> {
        let mut bytes = [0_u8; AUTH_CHALLENGE_BYTES];
        getrandom::fill(&mut bytes).map_err(|_| DeviceServiceError::EntropyUnavailable)?;
        let now = Instant::now();
        let expires_at = now
            .checked_add(self.challenge_ttl)
            .ok_or(DeviceServiceError::InvalidLifetime)?;

        let mut state = self.state();
        self.remove_expired_challenges(&mut state, now);
        if state.revoked_device_ids.contains(device_id) {
            return Err(DeviceServiceError::DeviceRevoked);
        }
        if !state.devices.contains_key(device_id) {
            return Err(DeviceServiceError::UnknownDevice);
        }

        let id = loop {
            let candidate = Uuid::new_v4();
            if !state.challenges.contains_key(&candidate) {
                break candidate;
            }
        };
        state.challenges.insert(
            id,
            ChallengeRecord {
                bytes,
                device_id: device_id.to_owned(),
                expires_at,
            },
        );

        Ok(DeviceAuthChallenge {
            id,
            bytes,
            device_id: device_id.to_owned(),
        })
    }

    pub fn authenticate(
        &self,
        challenge_id: Uuid,
        proof: DeviceAuthProof,
    ) -> Result<IssuedDeviceSession, DeviceServiceError> {
        let now = Instant::now();
        let (challenge, device) = {
            let mut state = self.state();
            let challenge = state
                .challenges
                .remove(&challenge_id)
                .ok_or(DeviceServiceError::UnknownChallenge)?;
            if now >= challenge.expires_at {
                return Err(DeviceServiceError::ExpiredChallenge);
            }
            if proof.device_id != challenge.device_id {
                return Err(DeviceServiceError::InvalidProof);
            }
            let device = state
                .devices
                .get(&challenge.device_id)
                .cloned()
                .ok_or(DeviceServiceError::UnknownDevice)?;
            (challenge, device)
        };

        proof
            .verify(&device.certificate, challenge_id.as_bytes(), &challenge.bytes)
            .map_err(|_| DeviceServiceError::InvalidProof)?;

        let expires_at = now
            .checked_add(self.session_ttl)
            .ok_or(DeviceServiceError::InvalidLifetime)?;
        let mut token = [0_u8; SESSION_TOKEN_BYTES];
        let token_digest = loop {
            getrandom::fill(&mut token).map_err(|_| DeviceServiceError::EntropyUnavailable)?;
            let digest = session_token_digest(&token);
            if !self.state().sessions.contains_key(&digest) {
                break digest;
            }
        };

        let mut state = self.state();
        self.remove_expired_sessions(&mut state, now);
        if state.revoked_device_ids.contains(&challenge.device_id)
            || !state.devices.contains_key(&challenge.device_id)
        {
            return Err(DeviceServiceError::DeviceRevoked);
        }
        state.sessions.insert(
            token_digest,
            SessionRecord {
                device_id: challenge.device_id,
                expires_at,
            },
        );

        Ok(IssuedDeviceSession {
            token,
            expires_in: self.session_ttl,
        })
    }

    pub fn authorize_session(
        &self,
        token: &[u8; SESSION_TOKEN_BYTES],
    ) -> Result<RegisteredDevice, DeviceServiceError> {
        let digest = session_token_digest(token);
        let now = Instant::now();
        let mut state = self.state();
        let Some(session) = state.sessions.get(&digest).cloned() else {
            return Err(DeviceServiceError::InvalidSession);
        };
        if now >= session.expires_at {
            state.sessions.remove(&digest);
            return Err(DeviceServiceError::ExpiredSession);
        }
        if state.revoked_device_ids.contains(&session.device_id) {
            state.sessions.remove(&digest);
            return Err(DeviceServiceError::InvalidSession);
        }
        state
            .devices
            .get(&session.device_id)
            .cloned()
            .ok_or(DeviceServiceError::InvalidSession)
    }

    pub fn device(&self, device_id: &str) -> Option<RegisteredDevice> {
        self.state().devices.get(device_id).cloned()
    }

    pub fn device_by_mailbox(&self, mailbox_id: &str) -> Option<RegisteredDevice> {
        let state = self.state();
        let device_id = state.mailbox_to_device.get(mailbox_id)?;
        state.devices.get(device_id).cloned()
    }

    pub fn revoke_device(&self, device_id: &str) -> Result<(), DeviceServiceError> {
        let mut state = self.state();
        let device = state
            .devices
            .remove(device_id)
            .ok_or(DeviceServiceError::UnknownDevice)?;
        state
            .mailbox_to_device
            .remove(&device.certificate.mailbox_id);
        state.revoked_device_ids.insert(device_id.to_owned());
        state
            .challenges
            .retain(|_, challenge| challenge.device_id != device_id);
        state
            .sessions
            .retain(|_, session| session.device_id != device_id);
        Ok(())
    }

    fn remove_expired_challenges(&self, state: &mut DeviceServiceState, now: Instant) {
        state
            .challenges
            .retain(|_, challenge| challenge.expires_at > now);
    }

    fn remove_expired_sessions(&self, state: &mut DeviceServiceState, now: Instant) {
        state
            .sessions
            .retain(|_, session| session.expires_at > now);
    }

    fn state(&self) -> MutexGuard<'_, DeviceServiceState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn session_token_digest(token: &[u8; SESSION_TOKEN_BYTES]) -> [u8; 32] {
    let digest = Sha256::digest(token);
    let mut result = [0_u8; 32];
    result.copy_from_slice(&digest);
    result
}
