#![forbid(unsafe_code)]

use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind = env::var("MESSENGER_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_owned());
    let listener = tokio::net::TcpListener::bind(&bind).await?;

    axum::serve(listener, messenger_gateway::app()).await?;
    Ok(())
}
