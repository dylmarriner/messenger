#![forbid(unsafe_code)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

const CONTACT_CARD_VERSION: u8 = 1;
const REGISTRATION_PROOF_VERSION: u8 = 1;
const KEY_PACKAGE_BINDING_VERSION: u8 = 1;
const ACCOUNT_ID_PREFIX: &str = "a1_";
const CONTACT_CARD_DOMAIN: &[u8] = b"messenger-contact-card-v1\0";
const REGISTRATION_DOMAIN: &[u8] = b"messenger-registration-v1\0";
const KEY_PACKAGE_BINDING_DOMAIN: &[u8] = b"messenger-key-package-binding-v1\0";
const ACCOUNT_ID_BYTES: usize = 16;
const DEVICE_ID_BYTES: usize = 16;
const ROOT_SECRET_BYTES: usize = 32;
const ROOT_PUBLIC_KEY_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const CHALLENGE_ID_BYTES: usize = 16;
const CHALLENGE_BYTES: usize = 32;

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationProof {
    pub version: u8,
    pub account_id: String,
    pub root_public_key: String,
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPackageBinding {
    pub version: u8,
    pub account_id: String,
    pub root_public_key: String,
    pub device_id: String,
    pub signature: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("operating-system entropy source unavailable")]
    EntropyUnavailable,
    #[error("unsupported contact-card version {0}")]
    UnsupportedContactCardVersion(u8),
    #[error("unsupported registration-proof version {0}")]
    UnsupportedRegistrationProofVersion(u8),
    #[error("unsupported key-package-binding version {0}")]
    UnsupportedKeyPackageBindingVersion(u8),
    #[error("invalid account identifier")]
    InvalidAccountId,
    #[error("invalid device identifier")]
    InvalidDeviceId,
    #[error("invalid account-root public key")]
    InvalidPublicKey,
    #[error("invalid signature encoding")]
    InvalidSignature,
    #[error("signature verification failed")]
    VerificationFailed,
    #[error("key package is too large to bind")]
    KeyPackageTooLarge,
    #[error("key package binding does not match trusted contact identity")]
    ContactMismatch,
}

impl AccountIdentity {
    pub fn generate() -> Result<Self, CryptoError> {
        let mut account_id_raw = [0_u8; ACCOUNT_ID_BYTES];
        getrandom::fill(&mut account_id_raw).map_err(|_| CryptoError::EntropyUnavailable)?;

        let mut root_secret = Zeroizing::new([0_u8; ROOT_SECRET_BYTES]);
        getrandom::fill(root_secret.as_mut()).map_err(|_| CryptoError::EntropyUnavailable)?;
        let root_signing_key = SigningKey::from_bytes(root_secret.as_ref());

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

    pub fn registration_proof(
        &self,
        challenge_id: &[u8; CHALLENGE_ID_BYTES],
        challenge: &[u8; CHALLENGE_BYTES],
    ) -> RegistrationProof {
        let root_public_key = self.root_signing_key.verifying_key().to_bytes();
        let payload = registration_payload(
            challenge_id,
            challenge,
            &self.account_id_raw,
            &root_public_key,
        );
        let signature: Signature = self.root_signing_key.sign(&payload);

        RegistrationProof {
            version: REGISTRATION_PROOF_VERSION,
            account_id: self.account_id.clone(),
            root_public_key: URL_SAFE_NO_PAD.encode(root_public_key),
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        }
    }

    pub fn bind_key_package(
        &self,
        device_id: &[u8; DEVICE_ID_BYTES],
        key_package: &[u8],
    ) -> Result<KeyPackageBinding, CryptoError> {
        let key_package_len =
            u32::try_from(key_package.len()).map_err(|_| CryptoError::KeyPackageTooLarge)?;
        let root_public_key = self.root_signing_key.verifying_key().to_bytes();
        let payload = key_package_binding_payload(
            device_id,
            key_package_len,
            key_package,
            &self.account_id_raw,
            &root_public_key,
        );
        let signature: Signature = self.root_signing_key.sign(&payload);

        Ok(KeyPackageBinding {
            version: KEY_PACKAGE_BINDING_VERSION,
            account_id: self.account_id.clone(),
            root_public_key: URL_SAFE_NO_PAD.encode(root_public_key),
            device_id: URL_SAFE_NO_PAD.encode(device_id),
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        })
    }
}

impl ContactCard {
    pub fn verify(&self) -> Result<(), CryptoError> {
        if self.version != CONTACT_CARD_VERSION {
            return Err(CryptoError::UnsupportedContactCardVersion(self.version));
        }

        let account_id_raw = decode_account_id(&self.account_id)?;
        let root_public_key = decode_public_key(&self.root_public_key)?;
        let signature = decode_signature(&self.signature)?;
        let payload = contact_card_payload(&account_id_raw, &root_public_key);

        verify_strict(&root_public_key, &payload, &signature)
    }
}

impl RegistrationProof {
    pub fn verify(
        &self,
        challenge_id: &[u8; CHALLENGE_ID_BYTES],
        challenge: &[u8; CHALLENGE_BYTES],
    ) -> Result<(), CryptoError> {
        if self.version != REGISTRATION_PROOF_VERSION {
            return Err(CryptoError::UnsupportedRegistrationProofVersion(self.version));
        }

        let account_id_raw = decode_account_id(&self.account_id)?;
        let root_public_key = decode_public_key(&self.root_public_key)?;
        let signature = decode_signature(&self.signature)?;
        let payload = registration_payload(
            challenge_id,
            challenge,
            &account_id_raw,
            &root_public_key,
        );

        verify_strict(&root_public_key, &payload, &signature)
    }
}

impl KeyPackageBinding {
    pub fn verify(&self, key_package: &[u8]) -> Result<(), CryptoError> {
        if self.version != KEY_PACKAGE_BINDING_VERSION {
            return Err(CryptoError::UnsupportedKeyPackageBindingVersion(self.version));
        }

        let account_id_raw = decode_account_id(&self.account_id)?;
        let root_public_key = decode_public_key(&self.root_public_key)?;
        let device_id = decode_device_id(&self.device_id)?;
        let signature = decode_signature(&self.signature)?;
        let key_package_len =
            u32::try_from(key_package.len()).map_err(|_| CryptoError::KeyPackageTooLarge)?;
        let payload = key_package_binding_payload(
            &device_id,
            key_package_len,
            key_package,
            &account_id_raw,
            &root_public_key,
        );

        verify_strict(&root_public_key, &payload, &signature)
    }

    pub fn verify_for_contact(
        &self,
        contact: &ContactCard,
        key_package: &[u8],
    ) -> Result<(), CryptoError> {
        contact.verify()?;
        if self.account_id != contact.account_id || self.root_public_key != contact.root_public_key {
            return Err(CryptoError::ContactMismatch);
        }
        self.verify(key_package)
    }
}

fn verify_strict(
    root_public_key: &[u8; ROOT_PUBLIC_KEY_BYTES],
    payload: &[u8],
    signature: &Signature,
) -> Result<(), CryptoError> {
    let verifying_key = VerifyingKey::from_bytes(root_public_key)
        .map_err(|_| CryptoError::InvalidPublicKey)?;

    verifying_key
        .verify_strict(payload, signature)
        .map_err(|_| CryptoError::VerificationFailed)
}

fn decode_account_id(value: &str) -> Result<[u8; ACCOUNT_ID_BYTES], CryptoError> {
    let encoded = value
        .strip_prefix(ACCOUNT_ID_PREFIX)
        .ok_or(CryptoError::InvalidAccountId)?;

    decode_fixed::<ACCOUNT_ID_BYTES, _>(encoded, || CryptoError::InvalidAccountId)
}

fn decode_device_id(value: &str) -> Result<[u8; DEVICE_ID_BYTES], CryptoError> {
    decode_fixed::<DEVICE_ID_BYTES, _>(value, || CryptoError::InvalidDeviceId)
}

fn decode_public_key(value: &str) -> Result<[u8; ROOT_PUBLIC_KEY_BYTES], CryptoError> {
    decode_fixed::<ROOT_PUBLIC_KEY_BYTES, _>(value, || CryptoError::InvalidPublicKey)
}

fn decode_signature(value: &str) -> Result<Signature, CryptoError> {
    let bytes = decode_fixed::<SIGNATURE_BYTES, _>(value, || CryptoError::InvalidSignature)?;
    Ok(Signature::from_bytes(&bytes))
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

fn registration_payload(
    challenge_id: &[u8; CHALLENGE_ID_BYTES],
    challenge: &[u8; CHALLENGE_BYTES],
    account_id_raw: &[u8; ACCOUNT_ID_BYTES],
    root_public_key: &[u8; ROOT_PUBLIC_KEY_BYTES],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(
        REGISTRATION_DOMAIN.len()
            + CHALLENGE_ID_BYTES
            + CHALLENGE_BYTES
            + ACCOUNT_ID_BYTES
            + ROOT_PUBLIC_KEY_BYTES,
    );
    payload.extend_from_slice(REGISTRATION_DOMAIN);
    payload.extend_from_slice(challenge_id);
    payload.extend_from_slice(challenge);
    payload.extend_from_slice(account_id_raw);
    payload.extend_from_slice(root_public_key);
    payload
}

fn key_package_binding_payload(
    device_id: &[u8; DEVICE_ID_BYTES],
    key_package_len: u32,
    key_package: &[u8],
    account_id_raw: &[u8; ACCOUNT_ID_BYTES],
    root_public_key: &[u8; ROOT_PUBLIC_KEY_BYTES],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(
        KEY_PACKAGE_BINDING_DOMAIN.len()
            + DEVICE_ID_BYTES
            + ACCOUNT_ID_BYTES
            + ROOT_PUBLIC_KEY_BYTES
            + size_of::<u32>()
            + key_package.len(),
    );
    payload.extend_from_slice(KEY_PACKAGE_BINDING_DOMAIN);
    payload.extend_from_slice(device_id);
    payload.extend_from_slice(account_id_raw);
    payload.extend_from_slice(root_public_key);
    payload.extend_from_slice(&key_package_len.to_be_bytes());
    payload.extend_from_slice(key_package);
    payload
}
