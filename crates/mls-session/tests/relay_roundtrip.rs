use messenger_mls_session::MlsClient;
use messenger_protocol::{ENVELOPE_VERSION, Envelope};
use messenger_relay::InMemoryRelay;
use uuid::Uuid;

#[test]
fn relay_transports_only_serialized_mls_ciphertext() {
    let alice = MlsClient::generate().expect("alice MLS client");
    let bob = MlsClient::generate().expect("bob MLS client");

    let bob_key_package = bob.key_package().expect("bob key package");
    let mut alice_group = alice.create_group().expect("alice group");
    let welcome = alice
        .add_member(&mut alice_group, &bob_key_package)
        .expect("add bob");
    let mut bob_group = bob.join_from_welcome(&welcome).expect("bob joins group");

    let plaintext = b"opaque relay vertical slice";
    let mls_ciphertext = alice
        .encrypt(&mut alice_group, plaintext)
        .expect("encrypt");

    assert!(!mls_ciphertext
        .windows(plaintext.len())
        .any(|window| window == plaintext));

    let relay = InMemoryRelay::default();
    relay
        .enqueue(Envelope {
            version: ENVELOPE_VERSION,
            envelope_id: Uuid::new_v4(),
            mailbox_id: "bob-device-mailbox".to_owned(),
            ciphertext: mls_ciphertext.clone(),
        })
        .expect("enqueue ciphertext");

    let delivered = relay.drain_mailbox("bob-device-mailbox");
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].ciphertext, mls_ciphertext);

    let decrypted = bob
        .decrypt(&mut bob_group, &delivered[0].ciphertext)
        .expect("bob decrypts");
    assert_eq!(decrypted, plaintext);
}
