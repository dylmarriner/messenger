use messenger_crypto_core::{AccountIdentity, ContactCard};

#[test]
fn generated_identities_are_distinct_and_cards_verify() {
    let alice = AccountIdentity::generate().expect("alice identity");
    let bob = AccountIdentity::generate().expect("bob identity");

    assert_ne!(alice.account_id(), bob.account_id());
    alice.contact_card().verify().expect("valid contact card");
    bob.contact_card().verify().expect("valid contact card");
}

#[test]
fn tampering_with_account_id_invalidates_contact_card() {
    let identity = AccountIdentity::generate().expect("identity");
    let card = identity.contact_card();

    let tampered = ContactCard {
        account_id: format!("{}x", card.account_id),
        ..card
    };

    assert!(tampered.verify().is_err());
}

#[test]
fn registration_proof_verifies_only_for_the_issued_challenge() {
    let identity = AccountIdentity::generate().expect("identity");
    let challenge_id = [0x11_u8; 16];
    let challenge = [0x22_u8; 32];
    let proof = identity.registration_proof(&challenge_id, &challenge);

    proof
        .verify(&challenge_id, &challenge)
        .expect("valid registration proof");

    let mut changed_challenge = challenge;
    changed_challenge[0] ^= 0x01;
    assert!(proof.verify(&challenge_id, &changed_challenge).is_err());

    let mut changed_challenge_id = challenge_id;
    changed_challenge_id[15] ^= 0x01;
    assert!(proof.verify(&changed_challenge_id, &challenge).is_err());
}

#[test]
fn registration_proof_binds_account_id_and_root_public_key() {
    let identity = AccountIdentity::generate().expect("identity");
    let other_identity = AccountIdentity::generate().expect("other identity");
    let challenge_id = [0x33_u8; 16];
    let challenge = [0x44_u8; 32];
    let proof = identity.registration_proof(&challenge_id, &challenge);

    let mut changed_account = proof.clone();
    changed_account.account_id.push('x');
    assert!(changed_account.verify(&challenge_id, &challenge).is_err());

    let mut changed_key = proof;
    changed_key.root_public_key = other_identity.contact_card().root_public_key;
    assert!(changed_key.verify(&challenge_id, &challenge).is_err());
}

#[test]
fn key_package_binding_authenticates_exact_package_for_contact_root() {
    let identity = AccountIdentity::generate().expect("identity");
    let contact = identity.contact_card();
    let device_id = [0x55_u8; 16];
    let key_package = b"serialized-openmls-key-package";
    let binding = identity
        .bind_key_package(&device_id, key_package)
        .expect("key package binding");

    binding.verify(key_package).expect("self-verifying binding");
    binding
        .verify_for_contact(&contact, key_package)
        .expect("binding matches trusted contact");

    let mut tampered_package = key_package.to_vec();
    tampered_package[0] ^= 0x01;
    assert!(binding.verify(&tampered_package).is_err());
}

#[test]
fn key_package_binding_rejects_device_id_or_contact_substitution() {
    let identity = AccountIdentity::generate().expect("identity");
    let other_identity = AccountIdentity::generate().expect("other identity");
    let key_package = b"serialized-openmls-key-package";
    let binding = identity
        .bind_key_package(&[0x66_u8; 16], key_package)
        .expect("binding");
    let alternate_binding = identity
        .bind_key_package(&[0x77_u8; 16], key_package)
        .expect("alternate binding");

    let mut changed_device = binding.clone();
    changed_device.device_id = alternate_binding.device_id;
    assert!(changed_device.verify(key_package).is_err());

    assert!(
        binding
            .verify_for_contact(&other_identity.contact_card(), key_package)
            .is_err()
    );
}
