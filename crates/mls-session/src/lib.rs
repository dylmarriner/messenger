#![forbid(unsafe_code)]

use openmls::{
    prelude::{tls_codec::*, *},
    storage::OpenMlsProvider,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use thiserror::Error;

const DEVICE_CREDENTIAL_ID_BYTES: usize = 16;
const APPLICATION_PADDING_BYTES: usize = 256;
const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Per-device MLS context.
///
/// This type deliberately does not implement `Debug`, `Clone`, or serialization.
/// The provider and signer contain cryptographic state that must stay client-side.
pub struct MlsClient {
    device_id: [u8; DEVICE_CREDENTIAL_ID_BYTES],
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
}

/// Opaque project-level wrapper around OpenMLS group state.
///
/// Keeping the raw `MlsGroup` private prevents application code from bypassing
/// the protocol policy centralized in this crate.
pub struct MlsGroupState {
    group: MlsGroup,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MlsError {
    #[error("operating-system entropy source unavailable")]
    EntropyUnavailable,
    #[error("failed to generate MLS credential signing key")]
    CredentialKeyGeneration,
    #[error("failed to store MLS credential signing key")]
    CredentialKeyStorage,
    #[error("failed to create MLS KeyPackage")]
    KeyPackageCreation,
    #[error("failed to serialize MLS object")]
    Serialization,
    #[error("failed to parse MLS KeyPackage")]
    KeyPackageParsing,
    #[error("MLS KeyPackage validation failed")]
    KeyPackageValidation,
    #[error("MLS KeyPackage credential identity does not match the authorized device")]
    CredentialIdentityMismatch,
    #[error("failed to create MLS group")]
    GroupCreation,
    #[error("failed to add MLS member")]
    MemberAdd,
    #[error("failed to merge MLS membership commit")]
    PendingCommitMerge,
    #[error("failed to parse MLS Welcome")]
    WelcomeParsing,
    #[error("failed to join MLS group from Welcome")]
    WelcomeJoin,
    #[error("failed to encrypt MLS application message")]
    MessageEncryption,
    #[error("failed to parse MLS application message")]
    MessageParsing,
    #[error("incoming MLS object is not a protocol message")]
    ProtocolMessageExpected,
    #[error("MLS message authentication or processing failed")]
    MessageProcessing,
    #[error("incoming MLS message is not application data")]
    UnexpectedMessageType,
}

impl MlsClient {
    pub fn generate() -> Result<Self, MlsError> {
        let mut device_id = [0_u8; DEVICE_CREDENTIAL_ID_BYTES];
        getrandom::fill(&mut device_id).map_err(|_| MlsError::EntropyUnavailable)?;
        Self::generate_for_device(device_id)
    }

    pub fn generate_for_device(
        device_id: [u8; DEVICE_CREDENTIAL_ID_BYTES],
    ) -> Result<Self, MlsError> {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
            .map_err(|_| MlsError::CredentialKeyGeneration)?;
        signer
            .store(provider.storage())
            .map_err(|_| MlsError::CredentialKeyStorage)?;

        let basic_credential = BasicCredential::new(device_id.to_vec());
        let credential = CredentialWithKey {
            credential: basic_credential.into(),
            signature_key: signer.to_public_vec().into(),
        };

        Ok(Self {
            device_id,
            provider,
            signer,
            credential,
        })
    }

    pub fn device_id(&self) -> [u8; DEVICE_CREDENTIAL_ID_BYTES] {
        self.device_id
    }

    /// Creates a fresh, one-time MLS KeyPackage and returns only its public bytes.
    pub fn key_package(&self) -> Result<Vec<u8>, MlsError> {
        let key_package = KeyPackage::builder()
            .build(
                CIPHERSUITE,
                &self.provider,
                &self.signer,
                self.credential.clone(),
            )
            .map_err(|_| MlsError::KeyPackageCreation)?;

        key_package
            .key_package()
            .tls_serialize_detached()
            .map_err(|_| MlsError::Serialization)
    }

    /// Verifies the full KeyPackage and then requires its embedded BasicCredential
    /// identity to equal the account-authorized device identifier.
    pub fn validate_key_package_for_device(
        serialized_key_package: &[u8],
        expected_device_id: &[u8; DEVICE_CREDENTIAL_ID_BYTES],
    ) -> Result<(), MlsError> {
        let provider = OpenMlsRustCrypto::default();
        let key_package = validate_key_package(&provider, serialized_key_package)?;
        let basic_credential = BasicCredential::try_from(key_package.leaf_node().credential().clone())
            .map_err(|_| MlsError::CredentialIdentityMismatch)?;

        if basic_credential.identity() != expected_device_id {
            return Err(MlsError::CredentialIdentityMismatch);
        }
        Ok(())
    }

    pub fn create_group(&self) -> Result<MlsGroupState, MlsError> {
        let config = create_config();
        let group = MlsGroup::new(
            &self.provider,
            &self.signer,
            &config,
            self.credential.clone(),
        )
        .map_err(|_| MlsError::GroupCreation)?;

        Ok(MlsGroupState { group })
    }

    /// Validates and consumes another device's public KeyPackage, returning the
    /// serialized Welcome that must be delivered to that device.
    pub fn add_member(
        &self,
        group: &mut MlsGroupState,
        serialized_key_package: &[u8],
    ) -> Result<Vec<u8>, MlsError> {
        let key_package = validate_key_package(&self.provider, serialized_key_package)?;

        let (_, welcome, _) = group
            .group
            .add_members(
                &self.provider,
                &self.signer,
                core::slice::from_ref(&key_package),
            )
            .map_err(|_| MlsError::MemberAdd)?;

        group
            .group
            .merge_pending_commit(&self.provider)
            .map_err(|_| MlsError::PendingCommitMerge)?;

        welcome.to_bytes().map_err(|_| MlsError::Serialization)
    }

    pub fn join_from_welcome(&self, serialized_welcome: &[u8]) -> Result<MlsGroupState, MlsError> {
        let message = MlsMessageIn::tls_deserialize_exact(serialized_welcome)
            .map_err(|_| MlsError::WelcomeParsing)?;
        let welcome = message
            .into_welcome()
            .map_err(|_| MlsError::WelcomeParsing)?;

        let staged = StagedWelcome::new_from_welcome(
            &self.provider,
            &join_config(),
            welcome,
            None,
        )
        .map_err(|_| MlsError::WelcomeJoin)?;
        let group = staged
            .into_group(&self.provider)
            .map_err(|_| MlsError::WelcomeJoin)?;

        Ok(MlsGroupState { group })
    }

    pub fn encrypt(
        &self,
        group: &mut MlsGroupState,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, MlsError> {
        group
            .group
            .create_message(&self.provider, &self.signer, plaintext)
            .map_err(|_| MlsError::MessageEncryption)?
            .to_bytes()
            .map_err(|_| MlsError::Serialization)
    }

    pub fn decrypt(
        &self,
        group: &mut MlsGroupState,
        serialized_message: &[u8],
    ) -> Result<Vec<u8>, MlsError> {
        let message = MlsMessageIn::tls_deserialize_exact(serialized_message)
            .map_err(|_| MlsError::MessageParsing)?;
        let protocol_message = message
            .try_into_protocol_message()
            .map_err(|_| MlsError::ProtocolMessageExpected)?;
        let processed = group
            .group
            .process_message(&self.provider, protocol_message)
            .map_err(|_| MlsError::MessageProcessing)?;

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(application_message) => {
                Ok(application_message.into_bytes())
            }
            _ => Err(MlsError::UnexpectedMessageType),
        }
    }
}

fn validate_key_package(
    provider: &OpenMlsRustCrypto,
    serialized_key_package: &[u8],
) -> Result<KeyPackage, MlsError> {
    KeyPackageIn::tls_deserialize_exact(serialized_key_package)
        .map_err(|_| MlsError::KeyPackageParsing)?
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|_| MlsError::KeyPackageValidation)
}

fn create_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .padding_size(APPLICATION_PADDING_BYTES)
        .use_ratchet_tree_extension(true)
        .build()
}

fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .padding_size(APPLICATION_PADDING_BYTES)
        .use_ratchet_tree_extension(true)
        .build()
}
