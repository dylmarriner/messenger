#![forbid(unsafe_code)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

const CONTACT_CARD_VERSION: u8 = 1;
const ACCOUNT_ID_PREFIX: &str = "a1_";
const CONTACT_CARD_DOMAIN: &[u8] = b"messenger-contact-card-v1\0";
const ACCOUNT_ID_BYTES: usize = 16;
const ROOT_SECRET_BYTES: usize = 32;
const ROOT_PUBLIC_KEY_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;

/// Client-held anonymous account identity.
///
/// This type intentionally does not implement `Serialize` or `Debug` so the
/// account-root signing key cannot accidentally cross an API/logging boundary.
pub struct AccountIdentity {
    account_id: String,
    account_id_raw: [u8; ACCOUNT_ID_BYTES],
    root_signing_key: SigningKey,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactCard {
    pub version: u8,
    pub account_id: String,
    pub root_public_key: String,
    pub signature: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("operating-system entropy source unavailable")]
    EntropyUnavailable,
    #[error("unsupported contact-card version {0}")]
    UnsupportedContactCardVersion(u8),
    #[error("invalid account identifier")]
    InvalidAccountId,
    #[error("invalid account-root public key")]
    InvalidPublicKey,
    #[error("invalid contact-card signature encoding")]
    InvalidSignature,
    #[error("contact-card signature verification failed")]
    VerificationFailed,
}

impl AccountIdentity {
    pub fn generate() -> Result<Self, CryptoError> {
        let mut account_id_raw = [0_u8; ACCOUNT_ID_BYTES];
        getrandom::fill(&mut account_id_raw).map_err(|_| CryptoError::EntropyUnavailable)?;

        let mut root_secret = [0_u8; ROOT_SECRET_BYTES];
        getrandom::fill(&mut root_secret).map_err(|_| CryptoError::EntropyUnavailable)?;
        let root_signing_key = SigningKey::from_bytes(&root_secret);
        root_secret.zeroize();

        let account_id = format!(
            "{ACCOUNT_ID_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(account_id_raw)
        );

        Ok(Self {
            account_id,
            account_id_raw,
            root_signing_key,
        })
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn contact_card(&self) -> ContactCard {
        let root_public_key = self.root_signing_key.verifying_key().to_bytes();
        let payload = contact_card_payload(&self.account_id_raw, &root_public_key);
        let signature: Signature = self.root_signing_key.sign(&payload);

        ContactCard {
            version: CONTACT_CARD_VERSION,
            account_id: self.account_id.clone(),
            root_public_key: URL_SAFE_NO_PAD.encode(root_public_key),
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        }
    }
}

impl ContactCard {
    pub fn verify(&self) -> Result<(), CryptoError> {
        if self.version != CONTACT_CARD_VERSION {
            return Err(CryptoError::UnsupportedContactCardVersion(self.version));
        }

        let account_id_raw = decode_account_id(&self.account_id)?;
        let root_public_key = decode_fixed::<ROOT_PUBLIC_KEY_BYTES, _>(
            &self.root_public_key,
            || CryptoError::InvalidPublicKey,
        )?;
        let signature_bytes = decode_fixed::<SIGNATURE_BYTES, _>(
            &self.signature,
            || CryptoError::InvalidSignature,
        )?;

        let verifying_key = VerifyingKey::from_bytes(&root_public_key)
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        let signature = Signature::from_bytes(&signature_bytes);
        let payload = contact_card_payload(&account_id_raw, &root_public_key);

        verifying_key
            .verify_strict(&payload, &signature)
            .map_err(|_| CryptoError::VerificationFailed)
    }
}

fn decode_account_id(value: &str) -> Result<[u8; ACCOUNT_ID_BYTES], CryptoError> {
    let encoded = value
        .strip_prefix(ACCOUNT_ID_PREFIX)
        .ok_or(CryptoError::InvalidAccountId)?;

    decode_fixed::<ACCOUNT_ID_BYTES, _>(encoded, || CryptoError::InvalidAccountId)
}

fn decode_fixed<const N: usize, F>(value: &str, error: F) -> Result<[u8; N], CryptoError>
where
    F: Fn() -> CryptoError,
{
    let decoded = URL_SAFE_NO_PAD.decode(value).map_err(|_| error())?;
    decoded.try_into().map_err(|_| error())
}

fn contact_card_payload(
    account_id_raw: &[u8; ACCOUNT_ID_BYTES],
    root_public_key: &[u8; ROOT_PUBLIC_KEY_BYTES],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(
        CONTACT_CARD_DOMAIN.len() + ACCOUNT_ID_BYTES + ROOT_PUBLIC_KEY_BYTES,
    );
    payload.extend_from_slice(CONTACT_CARD_DOMAIN);
    payload.extend_from_slice(account_id_raw);
    payload.extend_from_slice(root_public_key);
    payload
}
