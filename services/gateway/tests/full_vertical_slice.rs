use axum::{
    body::{Body, to_bytes},
    http::{
        Method, Request, StatusCode,
        header::{AUTHORIZATION, CONTENT_TYPE},
    },
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use messenger_crypto_core::{AccountIdentity, DeviceIdentity};
use messenger_gateway::{
    DeviceAuthChallengeRequest, DeviceAuthChallengeResponse, DeviceRegistrationRequest,
    DeviceSessionRequest, DeviceSessionResponse, EnvelopeSubmitRequest, KeyPackageClaimRequest,
    KeyPackageResponse, KeyPackageUploadRequest, MailboxAckRequest, MailboxResponse,
    RegistrationChallengeResponse, RegistrationRequest, app,
};
use messenger_mls_session::MlsClient;
use serde::Serialize;
use tower::ServiceExt;
use uuid::Uuid;

async fn post_json<T: Serialize>(router: &axum::Router, uri: &str, value: &T) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(uri)
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(value).expect("request JSON")))
                .expect("request"),
        )
        .await
        .expect("response")
}

async fn register_account(router: &axum::Router, account: &AccountIdentity) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/registration/challenge")
                .body(Body::empty())
                .expect("challenge request"),
        )
        .await
        .expect("challenge response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), 4096)
        .await
        .expect("challenge body");
    let challenge: RegistrationChallengeResponse =
        serde_json::from_slice(&body).expect("challenge JSON");
    let challenge_bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&challenge.challenge)
        .expect("challenge base64url")
        .try_into()
        .expect("challenge size");
    let proof = account.registration_proof(challenge.challenge_id.as_bytes(), &challenge_bytes);
    let response = post_json(
        router,
        "/v1/registration",
        &RegistrationRequest {
            challenge_id: challenge.challenge_id,
            proof,
        },
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
}

async fn authenticate_device(router: &axum::Router, device: &DeviceIdentity) -> String {
    let response = post_json(
        router,
        "/v1/device-auth/challenge",
        &DeviceAuthChallengeRequest {
            device_id: device.device_id_encoded().to_owned(),
        },
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), 4096)
        .await
        .expect("device challenge body");
    let challenge: DeviceAuthChallengeResponse =
        serde_json::from_slice(&body).expect("device challenge JSON");
    let challenge_bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&challenge.challenge)
        .expect("device challenge base64url")
        .try_into()
        .expect("device challenge size");
    let proof = device.authentication_proof(challenge.challenge_id.as_bytes(), &challenge_bytes);
    let response = post_json(
        router,
        "/v1/device-auth/session",
        &DeviceSessionRequest {
            challenge_id: challenge.challenge_id,
            proof,
        },
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), 4096)
        .await
        .expect("device session body");
    let session: DeviceSessionResponse = serde_json::from_slice(&body).expect("session JSON");
    session.token
}

#[tokio::test]
async fn anonymous_registration_to_authenticated_e2ee_delivery_round_trip() {
    let router = app();

    // Bob creates all long-term identity material locally.
    let bob_account = AccountIdentity::generate().expect("Bob account");
    let bob_contact = bob_account.contact_card();
    let bob_device = DeviceIdentity::generate().expect("Bob device");
    let bob_certificate = bob_account.authorize_device(&bob_device);
    let bob_mls = MlsClient::generate_for_device(bob_device.device_id()).expect("Bob MLS");

    register_account(&router, &bob_account).await;
    let device_registration = post_json(
        &router,
        "/v1/devices",
        &DeviceRegistrationRequest {
            certificate: bob_certificate.clone(),
        },
    )
    .await;
    assert_eq!(device_registration.status(), StatusCode::CREATED);

    // Bob publishes one root-authenticated, one-time MLS KeyPackage.
    let bob_key_package = bob_mls.key_package().expect("Bob KeyPackage");
    let bob_binding = bob_account
        .bind_key_package(&bob_device.device_id(), &bob_key_package)
        .expect("Bob KeyPackage binding");
    let upload = post_json(
        &router,
        "/v1/key-packages",
        &KeyPackageUploadRequest {
            key_package: URL_SAFE_NO_PAD.encode(&bob_key_package),
            binding: bob_binding,
        },
    )
    .await;
    assert_eq!(upload.status(), StatusCode::CREATED);

    // Alice claims public bootstrap material and authenticates it against the
    // root key she learned from Bob's QR/contact card.
    let claim = post_json(
        &router,
        "/v1/key-packages/claim",
        &KeyPackageClaimRequest {
            account_id: bob_account.account_id().to_owned(),
        },
    )
    .await;
    assert_eq!(claim.status(), StatusCode::OK);
    let body = to_bytes(claim.into_body(), 128 * 1024)
        .await
        .expect("claim body");
    let claimed: KeyPackageResponse = serde_json::from_slice(&body).expect("claim JSON");
    let claimed_key_package = URL_SAFE_NO_PAD
        .decode(&claimed.key_package)
        .expect("KeyPackage base64url");

    claimed
        .device_certificate
        .verify()
        .expect("device certificate signature");
    assert_eq!(claimed.device_certificate.account_id, bob_contact.account_id);
    assert_eq!(
        claimed.device_certificate.root_public_key,
        bob_contact.root_public_key
    );
    assert_eq!(claimed.binding.device_id, claimed.device_certificate.device_id);
    claimed
        .binding
        .verify_for_contact(&bob_contact, &claimed_key_package)
        .expect("root-authenticated KeyPackage");
    MlsClient::validate_key_package_for_device(&claimed_key_package, &bob_device.device_id())
        .expect("embedded MLS device identity");

    let alice_mls = MlsClient::generate().expect("Alice MLS");
    let mut alice_group = alice_mls.create_group().expect("Alice group");
    let welcome = alice_mls
        .add_member(&mut alice_group, &claimed_key_package)
        .expect("add authenticated Bob");
    let mut bob_group = bob_mls
        .join_from_welcome(&welcome)
        .expect("Bob joins");

    // Plaintext exists only at Alice and Bob. The HTTP relay receives MLS bytes.
    let plaintext = b"first complete anonymous E2EE vertical slice";
    let ciphertext = alice_mls
        .encrypt(&mut alice_group, plaintext)
        .expect("Alice encrypts");
    assert!(!ciphertext
        .windows(plaintext.len())
        .any(|window| window == plaintext));

    let envelope_id = Uuid::new_v4();
    let submit = post_json(
        &router,
        "/v1/envelopes",
        &EnvelopeSubmitRequest {
            version: 1,
            envelope_id,
            mailbox_id: claimed.device_certificate.mailbox_id.clone(),
            ciphertext: URL_SAFE_NO_PAD.encode(&ciphertext),
        },
    )
    .await;
    assert_eq!(submit.status(), StatusCode::ACCEPTED);

    // Bob authenticates with the independent device-auth key, not account root.
    let session_token = authenticate_device(&router, &bob_device).await;
    let mailbox = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/mailbox")
                .header(AUTHORIZATION, format!("Bearer {session_token}"))
                .body(Body::empty())
                .expect("mailbox request"),
        )
        .await
        .expect("mailbox response");
    assert_eq!(mailbox.status(), StatusCode::OK);
    let body = to_bytes(mailbox.into_body(), 256 * 1024)
        .await
        .expect("mailbox body");
    let mailbox: MailboxResponse = serde_json::from_slice(&body).expect("mailbox JSON");
    assert_eq!(mailbox.envelopes.len(), 1);
    assert_eq!(mailbox.envelopes[0].envelope_id, envelope_id);
    let delivered_ciphertext = URL_SAFE_NO_PAD
        .decode(&mailbox.envelopes[0].ciphertext)
        .expect("ciphertext base64url");
    assert_eq!(delivered_ciphertext, ciphertext);

    let decrypted = bob_mls
        .decrypt(&mut bob_group, &delivered_ciphertext)
        .expect("Bob decrypts locally");
    assert_eq!(decrypted, plaintext);

    let ack = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/mailbox/ack")
                .header(AUTHORIZATION, format!("Bearer {session_token}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&MailboxAckRequest {
                        envelope_ids: vec![envelope_id],
                    })
                    .expect("ack JSON"),
                ))
                .expect("ack request"),
        )
        .await
        .expect("ack response");
    assert_eq!(ack.status(), StatusCode::OK);

    let empty = router
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/mailbox")
                .header(AUTHORIZATION, format!("Bearer {session_token}"))
                .body(Body::empty())
                .expect("empty mailbox request"),
        )
        .await
        .expect("empty mailbox response");
    let body = to_bytes(empty.into_body(), 4096)
        .await
        .expect("empty mailbox body");
    let empty: MailboxResponse = serde_json::from_slice(&body).expect("empty mailbox JSON");
    assert!(empty.envelopes.is_empty());
}
