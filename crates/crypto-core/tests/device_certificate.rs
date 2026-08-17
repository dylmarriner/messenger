use messenger_crypto_core::{AccountIdentity, DeviceIdentity};

#[test]
fn device_certificate_is_bound_to_trusted_contact_root_and_exposes_device_bytes() {
    let account = AccountIdentity::generate().expect("account");
    let other = AccountIdentity::generate().expect("other account");
    let device = DeviceIdentity::generate().expect("device");
    let certificate = account.authorize_device(&device);

    certificate
        .verify_for_contact(&account.contact_card())
        .expect("trusted contact certificate");
    assert_eq!(certificate.device_id_bytes().expect("device id"), device.device_id());
    assert!(
        certificate
            .verify_for_contact(&other.contact_card())
            .is_err()
    );
}
