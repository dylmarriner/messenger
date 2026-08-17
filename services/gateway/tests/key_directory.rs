use axum::{
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header::CONTENT_TYPE},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use messenger_crypto_core::AccountIdentity;
use messenger_gateway::{
    KeyPackageClaimRequest, KeyPackageResponse, KeyPackageUploadRequest,
    RegistrationChallengeResponse, RegistrationRequest, app,
};
use messenger_mls_session::MlsClient;
use messenger_protocol::{ENVELOPE_VERSION, Envelope};
use messenger_relay::InMemoryRelay;
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

async fn register_identity(router: &axum::Router, identity: &AccountIdentity) {
    let challenge_response = router
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
    assert_eq!(challenge_response.status(), StatusCode::CREATED);

    let body = to_bytes(challenge_response.into_body(), 4096)
        .await
        .expect("challenge body");
    let challenge_response: RegistrationChallengeResponse =
        serde_json::from_slice(&body).expect("challenge JSON");
    let challenge: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&challenge_response.challenge)
        .expect("base64url challenge")
        .try_into()
        .expect("32-byte challenge");
    let proof = identity.registration_proof(challenge_response.challenge_id.as_bytes(), &challenge);

    let response = post_json(
        router,
        "/v1/registration",
        &RegistrationRequest {
            challenge_id: challenge_response.challenge_id,
            proof,
        },
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn trusted_contact_authenticates_claimed_key_package_before_e2ee_relay() {
    let router = app();
    let bob_identity = AccountIdentity::generate().expect("bob identity");
    let bob_contact = bob_identity.contact_card();
    let bob_mls = MlsClient::generate().expect("bob MLS client");
    register_identity(&router, &bob_identity).await;

    let bob_key_package = bob_mls.key_package().expect("bob KeyPackage");
    let binding = bob_identity
        .bind_key_package(&bob_mls.device_id(), &bob_key_package)
        .expect("root-signed KeyPackage");

    let upload = post_json(
        &router,
        "/v1/key-packages",
        &KeyPackageUploadRequest {
            key_package: URL_SAFE_NO_PAD.encode(&bob_key_package),
            binding,
        },
    )
    .await;
    assert_eq!(upload.status(), StatusCode::CREATED);

    let claim = post_json(
        &router,
        "/v1/key-packages/claim",
        &KeyPackageClaimRequest {
            account_id: bob_identity.account_id().to_owned(),
        },
    )
    .await;
    assert_eq!(claim.status(), StatusCode::OK);
    let body = to_bytes(claim.into_body(), 128 * 1024)
        .await
        .expect("claim body");
    let claimed: KeyPackageResponse = serde_json::from_slice(&body).expect("claim JSON");
    let claimed_bytes = URL_SAFE_NO_PAD
        .decode(&claimed.key_package)
        .expect("claimed KeyPackage base64url");
    assert_eq!(claimed_bytes, bob_key_package);
    claimed
        .binding
        .verify_for_contact(&bob_contact, &claimed_bytes)
        .expect("KeyPackage belongs to QR-authenticated Bob");

    let alice_mls = MlsClient::generate().expect("alice MLS client");
    let mut alice_group = alice_mls.create_group().expect("alice group");
    let welcome = alice_mls
        .add_member(&mut alice_group, &claimed_bytes)
        .expect("add authenticated Bob");
    let mut bob_group = bob_mls
        .join_from_welcome(&welcome)
        .expect("Bob joins group");

    let plaintext = b"authenticated end-to-end encrypted message";
    let ciphertext = alice_mls
        .encrypt(&mut alice_group, plaintext)
        .expect("Alice encrypts locally");
    assert!(!ciphertext
        .windows(plaintext.len())
        .any(|window| window == plaintext));

    let relay = InMemoryRelay::default();
    relay
        .enqueue(Envelope {
            version: ENVELOPE_VERSION,
            envelope_id: Uuid::new_v4(),
            mailbox_id: "bob-device-mailbox".to_owned(),
            ciphertext: ciphertext.clone(),
        })
        .expect("relay enqueue");
    let delivered = relay.drain_mailbox("bob-device-mailbox");
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].ciphertext, ciphertext);

    let decrypted = bob_mls
        .decrypt(&mut bob_group, &delivered[0].ciphertext)
        .expect("Bob decrypts locally");
    assert_eq!(decrypted, plaintext);

    let second_claim = post_json(
        &router,
        "/v1/key-packages/claim",
        &KeyPackageClaimRequest {
            account_id: bob_identity.account_id().to_owned(),
        },
    )
    .await;
    assert_eq!(second_claim.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn directory_rejects_key_package_modified_after_root_signature() {
    let router = app();
    let identity = AccountIdentity::generate().expect("identity");
    let mls = MlsClient::generate().expect("MLS client");
    register_identity(&router, &identity).await;

    let original = mls.key_package().expect("KeyPackage");
    let binding = identity
        .bind_key_package(&mls.device_id(), &original)
        .expect("binding");
    let mut tampered = original;
    let index = tampered.len() / 2;
    tampered[index] ^= 0x01;

    let response = post_json(
        &router,
        "/v1/key-packages",
        &KeyPackageUploadRequest {
            key_package: URL_SAFE_NO_PAD.encode(tampered),
            binding,
        },
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
