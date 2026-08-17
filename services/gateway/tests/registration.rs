use axum::{
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header::CONTENT_TYPE},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use messenger_crypto_core::AccountIdentity;
use messenger_gateway::{
    RegistrationChallengeResponse, RegistrationRequest, RegistrationResponse, app,
};
use tower::ServiceExt;

async fn issue_challenge(router: &axum::Router) -> RegistrationChallengeResponse {
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
    serde_json::from_slice(&body).expect("challenge JSON")
}

#[tokio::test]
async fn anonymous_registration_requires_account_root_key_possession() {
    let router = app();
    let identity = AccountIdentity::generate().expect("identity");
    let challenge_response = issue_challenge(&router).await;
    let challenge: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&challenge_response.challenge)
        .expect("base64url challenge")
        .try_into()
        .expect("32-byte challenge");
    let proof = identity.registration_proof(challenge_response.challenge_id.as_bytes(), &challenge);
    let request_body = serde_json::to_vec(&RegistrationRequest {
        challenge_id: challenge_response.challenge_id,
        proof,
    })
    .expect("registration JSON");

    let response = router
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/registration")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(request_body))
                .expect("registration request"),
        )
        .await
        .expect("registration response");

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), 4096)
        .await
        .expect("registration body");
    let registered: RegistrationResponse =
        serde_json::from_slice(&body).expect("registration response JSON");
    assert_eq!(registered.account_id, identity.account_id());
}

#[tokio::test]
async fn invalid_proof_is_generic_failure_and_consumes_challenge() {
    let router = app();
    let identity = AccountIdentity::generate().expect("identity");
    let challenge_response = issue_challenge(&router).await;
    let challenge: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&challenge_response.challenge)
        .expect("base64url challenge")
        .try_into()
        .expect("32-byte challenge");
    let valid_proof =
        identity.registration_proof(challenge_response.challenge_id.as_bytes(), &challenge);
    let mut invalid_proof = valid_proof.clone();
    invalid_proof.account_id.push('x');

    let invalid_request = serde_json::to_vec(&RegistrationRequest {
        challenge_id: challenge_response.challenge_id,
        proof: invalid_proof,
    })
    .expect("invalid registration JSON");
    let first = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/registration")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(invalid_request))
                .expect("invalid registration request"),
        )
        .await
        .expect("invalid registration response");
    assert_eq!(first.status(), StatusCode::UNAUTHORIZED);

    let replay_request = serde_json::to_vec(&RegistrationRequest {
        challenge_id: challenge_response.challenge_id,
        proof: valid_proof,
    })
    .expect("replay registration JSON");
    let replay = router
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/registration")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(replay_request))
                .expect("replay registration request"),
        )
        .await
        .expect("replay registration response");
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
}
