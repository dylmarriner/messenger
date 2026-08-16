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
