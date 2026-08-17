use messenger_mls_session::MlsClient;

#[test]
fn each_mls_client_has_a_distinct_device_scoped_identity() {
    let alice = MlsClient::generate().expect("alice MLS client");
    let bob = MlsClient::generate().expect("bob MLS client");

    assert_ne!(alice.device_id(), bob.device_id());
    assert_eq!(alice.device_id().len(), 16);
}
