use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header::CONTENT_TYPE},
};
use messenger_gateway::app;
use tower::ServiceExt;

#[tokio::test]
async fn health_endpoint_returns_json_ok() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("router response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(CONTENT_TYPE).expect("content type"),
        "application/json"
    );

    let body = to_bytes(response.into_body(), 1024)
        .await
        .expect("response body");
    assert_eq!(&body[..], br#"{"status":"ok"}"#);
}
