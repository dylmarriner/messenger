use std::time::Duration;

use messenger_crypto_core::{AccountIdentity, DeviceIdentity};
use messenger_device_service::{DeviceServiceError, InMemoryDeviceService};
use messenger_registration::RegisteredAccount;

fn registered_account(identity: &AccountIdentity) -> RegisteredAccount {
    let card = identity.contact_card();
    RegisteredAccount {
        account_id: card.account_id,
        root_public_key: card.root_public_key,
    }
}

#[test]
fn root_signed_device_registers_under_matching_anonymous_account() {
    let service = InMemoryDeviceService::new(Duration::from_secs(120), Duration::from_secs(900));
    let account_identity = AccountIdentity::generate().expect("account identity");
    let device_identity = DeviceIdentity::generate().expect("device identity");
    let certificate = account_identity.authorize_device(&device_identity);

    let registered = service
        .register_device(&registered_account(&account_identity), certificate.clone())
        .expect("register device");

    assert_eq!(registered.certificate, certificate);
    assert_eq!(
        service
            .device(device_identity.device_id_encoded())
            .expect("device lookup"),
        registered
    );
    assert_eq!(
        service
            .device_by_mailbox(device_identity.mailbox_id())
            .expect("mailbox lookup"),
        registered
    );
}

#[test]
fn device_certificate_cannot_be_registered_under_another_account() {
    let service = InMemoryDeviceService::default();
    let owner = AccountIdentity::generate().expect("owner");
    let other = AccountIdentity::generate().expect("other");
    let device = DeviceIdentity::generate().expect("device");
    let certificate = owner.authorize_device(&device);

    assert_eq!(
        service.register_device(&registered_account(&other), certificate),
        Err(DeviceServiceError::AccountMismatch)
    );
}

#[test]
fn valid_device_proof_issues_short_lived_session() {
    let service = InMemoryDeviceService::new(Duration::from_secs(120), Duration::from_secs(900));
    let account = AccountIdentity::generate().expect("account");
    let device = DeviceIdentity::generate().expect("device");
    let certificate = account.authorize_device(&device);
    service
        .register_device(&registered_account(&account), certificate.clone())
        .expect("register");

    let challenge = service
        .issue_challenge(device.device_id_encoded())
        .expect("challenge");
    let proof = device.authentication_proof(challenge.id.as_bytes(), &challenge.bytes);
    let session = service
        .authenticate(challenge.id, proof)
        .expect("authenticate");

    assert_eq!(session.expires_in, Duration::from_secs(900));
    assert_eq!(session.token.len(), 32);
    assert_eq!(
        service
            .authorize_session(&session.token)
            .expect("authorized session")
            .certificate,
        certificate
    );
}

#[test]
fn device_auth_challenge_is_single_use_even_after_bad_proof() {
    let service = InMemoryDeviceService::default();
    let account = AccountIdentity::generate().expect("account");
    let device = DeviceIdentity::generate().expect("device");
    service
        .register_device(
            &registered_account(&account),
            account.authorize_device(&device),
        )
        .expect("register");

    let challenge = service
        .issue_challenge(device.device_id_encoded())
        .expect("challenge");
    let valid_proof = device.authentication_proof(challenge.id.as_bytes(), &challenge.bytes);
    let mut invalid_proof = valid_proof.clone();
    invalid_proof.mailbox_id.push('x');

    assert_eq!(
        service.authenticate(challenge.id, invalid_proof),
        Err(DeviceServiceError::InvalidProof)
    );
    assert_eq!(
        service.authenticate(challenge.id, valid_proof),
        Err(DeviceServiceError::UnknownChallenge)
    );
}

#[test]
fn expired_device_challenge_is_rejected() {
    let service = InMemoryDeviceService::new(Duration::ZERO, Duration::from_secs(900));
    let account = AccountIdentity::generate().expect("account");
    let device = DeviceIdentity::generate().expect("device");
    service
        .register_device(
            &registered_account(&account),
            account.authorize_device(&device),
        )
        .expect("register");
    let challenge = service
        .issue_challenge(device.device_id_encoded())
        .expect("challenge");
    let proof = device.authentication_proof(challenge.id.as_bytes(), &challenge.bytes);

    assert_eq!(
        service.authenticate(challenge.id, proof),
        Err(DeviceServiceError::ExpiredChallenge)
    );
}

#[test]
fn expired_session_is_rejected() {
    let service = InMemoryDeviceService::new(Duration::from_secs(120), Duration::ZERO);
    let account = AccountIdentity::generate().expect("account");
    let device = DeviceIdentity::generate().expect("device");
    service
        .register_device(
            &registered_account(&account),
            account.authorize_device(&device),
        )
        .expect("register");
    let challenge = service
        .issue_challenge(device.device_id_encoded())
        .expect("challenge");
    let proof = device.authentication_proof(challenge.id.as_bytes(), &challenge.bytes);
    let session = service
        .authenticate(challenge.id, proof)
        .expect("authenticate");

    assert_eq!(
        service.authorize_session(&session.token),
        Err(DeviceServiceError::ExpiredSession)
    );
}

#[test]
fn revoking_device_invalidates_existing_sessions_and_routing() {
    let service = InMemoryDeviceService::default();
    let account = AccountIdentity::generate().expect("account");
    let device = DeviceIdentity::generate().expect("device");
    service
        .register_device(
            &registered_account(&account),
            account.authorize_device(&device),
        )
        .expect("register");
    let challenge = service
        .issue_challenge(device.device_id_encoded())
        .expect("challenge");
    let proof = device.authentication_proof(challenge.id.as_bytes(), &challenge.bytes);
    let session = service
        .authenticate(challenge.id, proof)
        .expect("authenticate");

    service
        .revoke_device(device.device_id_encoded())
        .expect("revoke");

    assert_eq!(
        service.authorize_session(&session.token),
        Err(DeviceServiceError::InvalidSession)
    );
    assert!(service.device(device.device_id_encoded()).is_none());
    assert!(service.device_by_mailbox(device.mailbox_id()).is_none());
}
