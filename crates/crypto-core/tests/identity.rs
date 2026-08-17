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
