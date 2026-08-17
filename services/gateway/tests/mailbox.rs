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
    DeviceSessionRequest, DeviceSessionResponse, EnvelopeSubmitRequest, MailboxAckRequest,
    MailboxAckResponse, MailboxResponse, RegistrationChallengeResponse, RegistrationRequest, app,
};
use serde::Serialize;
use tower::ServiceExt;
use uuid::Uuid;

async fn post_json<T: Serialize>(
    router: &axum::Router,
    uri: &str,
    value: &T,
) -> axum::response::Response {
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

async fn register_device(
    router: &axum::Router,
    account: &AccountIdentity,
    device: &DeviceIdentity,
) {
    let response = post_json(
        router,
        "/v1/devices",
        &DeviceRegistrationRequest {
            certificate: account.authorize_device(device),
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
        .expect("challenge base64url")
        .try_into()
        .expect("challenge size");
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
        .expect("session body");
    let session: DeviceSessionResponse = serde_json::from_slice(&body).expect("session JSON");
    assert_eq!(session.expires_in_seconds, 900);
    session.token
}

async fn get_mailbox(router: &axum::Router, token: &str) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/mailbox")
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .expect("mailbox request"),
        )
        .await
        .expect("mailbox response")
}

#[tokio::test]
async fn anonymous_submit_requires_authenticated_read_and_explicit_ack() {
    let router = app();
    let account = AccountIdentity::generate().expect("account");
    let device = DeviceIdentity::generate().expect("device");
    register_account(&router, &account).await;
    register_device(&router, &account, &device).await;
    let token = authenticate_device(&router, &device).await;

    let envelope_id = Uuid::new_v4();
    let ciphertext = vec![0x00, 0xff, 0x10, 0x20, 0x30];
    let submit = post_json(
        &router,
        "/v1/envelopes",
        &EnvelopeSubmitRequest {
            version: 1,
            envelope_id,
            mailbox_id: device.mailbox_id().to_owned(),
            ciphertext: URL_SAFE_NO_PAD.encode(&ciphertext),
        },
    )
    .await;
    assert_eq!(submit.status(), StatusCode::ACCEPTED);

    let first = get_mailbox(&router, &token).await;
    assert_eq!(first.status(), StatusCode::OK);
    let body = to_bytes(first.into_body(), 256 * 1024)
        .await
        .expect("mailbox body");
    let first: MailboxResponse = serde_json::from_slice(&body).expect("mailbox JSON");
    assert_eq!(first.envelopes.len(), 1);
    assert_eq!(first.envelopes[0].envelope_id, envelope_id);
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(&first.envelopes[0].ciphertext)
            .expect("ciphertext base64url"),
        ciphertext
    );

    let second = get_mailbox(&router, &token).await;
    let body = to_bytes(second.into_body(), 256 * 1024)
        .await
        .expect("second mailbox body");
    let second: MailboxResponse = serde_json::from_slice(&body).expect("second mailbox JSON");
    assert_eq!(second.envelopes.len(), 1);

    let ack = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/mailbox/ack")
                .header(AUTHORIZATION, format!("Bearer {token}"))
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
    let body = to_bytes(ack.into_body(), 4096).await.expect("ack body");
    let ack: MailboxAckResponse = serde_json::from_slice(&body).expect("ack response JSON");
    assert_eq!(ack.acknowledged, 1);

    let empty = get_mailbox(&router, &token).await;
    let body = to_bytes(empty.into_body(), 4096)
        .await
        .expect("empty mailbox body");
    let empty: MailboxResponse = serde_json::from_slice(&body).expect("empty mailbox JSON");
    assert!(empty.envelopes.is_empty());
}

#[tokio::test]
async fn invalid_bearer_token_cannot_read_or_ack_mailbox() {
    let router = app();
    let account = AccountIdentity::generate().expect("account");
    let device = DeviceIdentity::generate().expect("device");
    register_account(&router, &account).await;
    register_device(&router, &account, &device).await;

    let invalid_token = URL_SAFE_NO_PAD.encode([0x7f_u8; 32]);
    assert_eq!(
        get_mailbox(&router, &invalid_token).await.status(),
        StatusCode::UNAUTHORIZED
    );

    let ack = router
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/mailbox/ack")
                .header(AUTHORIZATION, format!("Bearer {invalid_token}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&MailboxAckRequest {
                        envelope_ids: vec![Uuid::new_v4()],
                    })
                    .expect("ack JSON"),
                ))
                .expect("ack request"),
        )
        .await
        .expect("ack response");
    assert_eq!(ack.status(), StatusCode::UNAUTHORIZED);
}
