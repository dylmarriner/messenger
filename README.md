# Messenger

High-assurance anonymous end-to-end encrypted messaging for Android and iOS.

> **Security status:** pre-audit development. This repository must not be described as government-certified or production-secure until independent cryptographic review, mobile security assessment, penetration testing, and operational review are complete.

## Architecture

- Native Android client: Kotlin + Jetpack Compose
- Native iOS client: Swift + SwiftUI
- Shared cryptographic core: Rust
- Messaging protocol: MLS (RFC 9420) via OpenMLS
- Backend: Rust + Axum + Tokio
- Data: PostgreSQL, Redis, NATS JetStream, S3-compatible object storage
- Calls: WebRTC/TURN; SFrame architecture for group media

## Privacy principles

1. No phone number or email required for registration.
2. Account identity is generated cryptographically on-device.
3. Message plaintext and attachment keys never reach the backend.
4. The relay treats message content as opaque ciphertext.
5. Push notifications are wake signals rather than message carriers.
6. Metadata anonymity is treated separately from content confidentiality.
7. No server-side master decryption or account-recovery key.

## Status

The repository is being scaffolded around the first vertical slice:

`anonymous registration -> cryptographic identity -> contact exchange -> encrypted one-to-one message -> relay -> recipient decryption`

Detailed design and implementation plans live under `docs/superpowers/`.
