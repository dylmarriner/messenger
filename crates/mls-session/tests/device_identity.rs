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

#[test]
fn validated_key_package_must_embed_the_expected_device_identity() {
    let expected_device_id = [0x43_u8; 16];
    let client = MlsClient::generate_for_device(expected_device_id).expect("MLS client");
    let key_package = client.key_package().expect("KeyPackage");

    MlsClient::validate_key_package_for_device(&key_package, &expected_device_id)
        .expect("matching BasicCredential identity");

    assert!(
        MlsClient::validate_key_package_for_device(&key_package, &[0x44_u8; 16]).is_err()
    );
}
