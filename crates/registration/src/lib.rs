#![forbid(unsafe_code)]

use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard},
    time::{Duration, Instant},
};

use messenger_crypto_core::RegistrationProof;
use thiserror::Error;
use uuid::Uuid;

const REGISTRATION_CHALLENGE_BYTES: usize = 32;
const DEFAULT_CHALLENGE_TTL: Duration = Duration::from_secs(300);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistrationChallenge {
    pub id: Uuid,
    pub bytes: [u8; REGISTRATION_CHALLENGE_BYTES],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredAccount {
    pub account_id: String,
    pub root_public_key: String,
}

pub struct InMemoryRegistrationService {
    ttl: Duration,
    state: Mutex<RegistrationState>,
}

#[derive(Default)]
struct RegistrationState {
    challenges: HashMap<Uuid, ChallengeRecord>,
    accounts: HashMap<String, RegisteredAccount>,
}

struct ChallengeRecord {
    bytes: [u8; REGISTRATION_CHALLENGE_BYTES],
    expires_at: Instant,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum RegistrationError {
    #[error("operating-system entropy source unavailable")]
    EntropyUnavailable,
    #[error("registration challenge lifetime is invalid")]
    InvalidChallengeLifetime,
    #[error("registration challenge is unknown or already consumed")]
    UnknownChallenge,
    #[error("registration challenge expired")]
    ExpiredChallenge,
    #[error("registration proof is invalid")]
    InvalidProof,
    #[error("account identifier is already bound to another root key")]
    AccountConflict,
}

impl Default for InMemoryRegistrationService {
    fn default() -> Self {
        Self::new(DEFAULT_CHALLENGE_TTL)
    }
}

impl InMemoryRegistrationService {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            state: Mutex::new(RegistrationState::default()),
        }
    }

    pub fn issue_challenge(&self) -> Result<RegistrationChallenge, RegistrationError> {
        let mut bytes = [0_u8; REGISTRATION_CHALLENGE_BYTES];
        getrandom::fill(&mut bytes).map_err(|_| RegistrationError::EntropyUnavailable)?;

        let now = Instant::now();
        let expires_at = now
            .checked_add(self.ttl)
            .ok_or(RegistrationError::InvalidChallengeLifetime)?;

        let mut state = self.state();
        self.remove_expired_challenges(&mut state, now);

        let id = loop {
            let candidate = Uuid::new_v4();
            if !state.challenges.contains_key(&candidate) {
                break candidate;
            }
        };

        state
            .challenges
            .insert(id, ChallengeRecord { bytes, expires_at });

        Ok(RegistrationChallenge { id, bytes })
    }

    pub fn register(
        &self,
        challenge_id: Uuid,
        proof: RegistrationProof,
    ) -> Result<RegisteredAccount, RegistrationError> {
        // Remove before verification. A challenge gets exactly one verification
        // attempt, whether that attempt succeeds or fails.
        let challenge = self
            .state()
            .challenges
            .remove(&challenge_id)
            .ok_or(RegistrationError::UnknownChallenge)?;

        if Instant::now() >= challenge.expires_at {
            return Err(RegistrationError::ExpiredChallenge);
        }

        proof
            .verify(challenge_id.as_bytes(), &challenge.bytes)
            .map_err(|_| RegistrationError::InvalidProof)?;

        let account = RegisteredAccount {
            account_id: proof.account_id,
            root_public_key: proof.root_public_key,
        };

        let mut state = self.state();
        if let Some(existing) = state.accounts.get(&account.account_id) {
            if existing.root_public_key == account.root_public_key {
                return Ok(existing.clone());
            }
            return Err(RegistrationError::AccountConflict);
        }

        state
            .accounts
            .insert(account.account_id.clone(), account.clone());
        Ok(account)
    }

    pub fn account(&self, account_id: &str) -> Option<RegisteredAccount> {
        self.state().accounts.get(account_id).cloned()
    }

    fn remove_expired_challenges(&self, state: &mut RegistrationState, now: Instant) {
        state
            .challenges
            .retain(|_, challenge| challenge.expires_at > now);
    }

    fn state(&self) -> MutexGuard<'_, RegistrationState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}
