use messenger_mls_session::MlsClient;

#[test]
fn each_mls_client_has_a_distinct_device_scoped_identity() {
    let alice = MlsClient::generate().expect("alice MLS client");
    let bob = MlsClient::generate().expect("bob MLS client");

    assert_ne!(alice.device_id(), bob.device_id());
    assert_eq!(alice.device_id().len(), 16);
}

#[test]
fn mls_can_use_the_account_authorized_device_identifier() {
    let device_id = [0x42_u8; 16];
    let client = MlsClient::generate_for_device(device_id).expect("MLS client");

    assert_eq!(client.device_id(), device_id);
}
