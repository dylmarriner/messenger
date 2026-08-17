use std::time::Duration;

use messenger_crypto_core::AccountIdentity;
use messenger_registration::{InMemoryRegistrationService, RegistrationError};

#[test]
fn valid_root_key_proof_registers_anonymous_account() {
    let service = InMemoryRegistrationService::new(Duration::from_secs(300));
    let identity = AccountIdentity::generate().expect("identity");
    let challenge = service.issue_challenge().expect("challenge");
    let proof = identity.registration_proof(challenge.id.as_bytes(), &challenge.bytes);

    let account = service
        .register(challenge.id, proof)
        .expect("registration succeeds");

    assert_eq!(account.account_id, identity.account_id());
    assert_eq!(service.account(identity.account_id()), Some(account));
}

#[test]
fn consumed_registration_challenge_cannot_be_replayed() {
    let service = InMemoryRegistrationService::new(Duration::from_secs(300));
    let identity = AccountIdentity::generate().expect("identity");
    let challenge = service.issue_challenge().expect("challenge");
    let proof = identity.registration_proof(challenge.id.as_bytes(), &challenge.bytes);

    service
        .register(challenge.id, proof.clone())
        .expect("first registration");

    assert_eq!(
        service.register(challenge.id, proof),
        Err(RegistrationError::UnknownChallenge)
    );
}

#[test]
fn expired_registration_challenge_is_rejected() {
    let service = InMemoryRegistrationService::new(Duration::ZERO);
    let identity = AccountIdentity::generate().expect("identity");
    let challenge = service.issue_challenge().expect("challenge");
    let proof = identity.registration_proof(challenge.id.as_bytes(), &challenge.bytes);

    assert_eq!(
        service.register(challenge.id, proof),
        Err(RegistrationError::ExpiredChallenge)
    );
}

#[test]
fn invalid_proof_is_rejected_and_consumes_challenge() {
    let service = InMemoryRegistrationService::new(Duration::from_secs(300));
    let identity = AccountIdentity::generate().expect("identity");
    let challenge = service.issue_challenge().expect("challenge");
    let valid_proof = identity.registration_proof(challenge.id.as_bytes(), &challenge.bytes);
    let mut invalid_proof = valid_proof.clone();
    invalid_proof.account_id.push('x');

    assert_eq!(
        service.register(challenge.id, invalid_proof),
        Err(RegistrationError::InvalidProof)
    );
    assert_eq!(
        service.register(challenge.id, valid_proof),
        Err(RegistrationError::UnknownChallenge)
    );
}
