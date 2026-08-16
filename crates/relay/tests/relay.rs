use messenger_protocol::Envelope;
use messenger_relay::InMemoryRelay;
use uuid::Uuid;

#[test]
fn relay_round_trips_ciphertext_without_interpreting_it() {
    let relay = InMemoryRelay::default();
    let ciphertext = vec![0x00, 0xff, 0x41, 0x42, 0x43];
    let envelope = Envelope {
        version: 1,
        envelope_id: Uuid::new_v4(),
        mailbox_id: "mailbox-test".to_owned(),
        ciphertext: ciphertext.clone(),
    };

    relay.enqueue(envelope).expect("enqueue");
    let drained = relay.drain_mailbox("mailbox-test");

    assert_eq!(drained.len(), 1);
    assert_eq!(drained[0].ciphertext, ciphertext);
}

#[test]
fn duplicate_envelope_ids_are_rejected() {
    let relay = InMemoryRelay::default();
    let id = Uuid::new_v4();
    let first = Envelope {
        version: 1,
        envelope_id: id,
        mailbox_id: "mailbox-test".to_owned(),
        ciphertext: vec![1, 2, 3],
    };
    let duplicate = first.clone();

    relay.enqueue(first).expect("first enqueue");
    assert!(relay.enqueue(duplicate).is_err());
}
