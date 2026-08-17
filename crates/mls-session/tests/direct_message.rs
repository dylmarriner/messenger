use messenger_mls_session::MlsClient;

fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|window| window == needle)
}

fn established_pair() -> (
    MlsClient,
    messenger_mls_session::MlsGroupState,
    MlsClient,
    messenger_mls_session::MlsGroupState,
) {
    let alice = MlsClient::generate().expect("alice MLS client");
    let bob = MlsClient::generate().expect("bob MLS client");

    let bob_key_package = bob.key_package().expect("bob key package");
    let mut alice_group = alice.create_group().expect("alice group");
    let welcome = alice
        .add_member(&mut alice_group, &bob_key_package)
        .expect("add bob");
    let bob_group = bob.join_from_welcome(&welcome).expect("bob joins group");

    (alice, alice_group, bob, bob_group)
}

#[test]
fn alice_encrypts_and_bob_decrypts_without_plaintext_on_the_wire() {
    let (alice, mut alice_group, bob, mut bob_group) = established_pair();
    let plaintext = b"the relay must never see this plaintext";

    let ciphertext = alice
        .encrypt(&mut alice_group, plaintext)
        .expect("encrypt application message");

    assert!(!contains_subsequence(&ciphertext, plaintext));

    let decrypted = bob
        .decrypt(&mut bob_group, &ciphertext)
        .expect("decrypt application message");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn modified_mls_ciphertext_is_rejected() {
    let (alice, mut alice_group, bob, mut bob_group) = established_pair();
    let mut ciphertext = alice
        .encrypt(&mut alice_group, b"authenticated message")
        .expect("encrypt application message");

    let index = ciphertext.len() / 2;
    ciphertext[index] ^= 0x01;

    assert!(bob.decrypt(&mut bob_group, &ciphertext).is_err());
}
