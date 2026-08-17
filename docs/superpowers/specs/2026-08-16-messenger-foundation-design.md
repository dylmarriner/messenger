# Messenger Foundation Design

## Scope

This specification covers the repository foundation and first security-sensitive vertical slice. It does not claim the product is production-secure, government-certified, or audit-complete.

## Architecture

- Native Android: Kotlin + Jetpack Compose.
- Native iOS: Swift + SwiftUI.
- Shared cryptographic core: Rust exposed through a narrow FFI boundary.
- Messaging protocol target: MLS RFC 9420 using OpenMLS 0.8.1, pinned behind a project-owned provider interface.
- Backend: Rust, Axum, Tokio, PostgreSQL, Redis, NATS JetStream and S3-compatible object storage.
- Calls: WebRTC with TURN relay by default; SFrame architecture for group-call media.

## Identity

Registration requires no phone number or email. The client creates a random 128-bit account identifier and an Ed25519 account-root signing key locally. Private root material never reaches the backend. Devices receive independent credentials signed by the account root in later tasks.

A version-1 contact card carries the account ID, account-root public key and Ed25519 signature. The signature covers a domain-separated fixed binary payload rather than JSON serialization so verification is deterministic across Swift, Kotlin and Rust implementations.

## Messaging

The eventual E2EE transport uses MLS for both two-party and group conversations. The server stores and routes only opaque envelopes. The first scaffold implements the opaque relay contract independently from MLS so relay persistence cannot accidentally acquire plaintext dependencies.

## Metadata model

Content confidentiality and metadata anonymity are separate properties. The default backend may observe source network information, delivery timing and destination mailboxes. Stronger relay/Tor modes are separate later work. Push payloads are wake-only and must not contain sender names or message text.

## Recovery

There is no server-side master decryption key. Recovery material is created and encrypted on the client. Losing all devices and recovery material is intentionally unrecoverable.

## Security invariants

1. Account-root private keys never cross the client/backend boundary.
2. Contact cards fail verification after any signed-field modification.
3. Relay envelopes are opaque byte strings to the server.
4. Duplicate envelope identifiers are rejected.
5. Reading a mailbox removes acknowledged messages only after explicit acknowledgement in the durable implementation; the scaffold keeps dequeue semantics simple and isolated.
6. No logging of plaintext, private keys, recovery secrets, attachment keys or message bodies.
7. Cryptographic dependencies are version-pinned and security advisories are release blockers.

## Initial repository boundaries

- `crates/crypto-core`: identity, contact verification, later MLS and attachment cryptography.
- `crates/protocol`: server-visible opaque envelope and API DTOs.
- `crates/relay`: message-relay abstraction and initial in-memory implementation.
- `services/gateway`: HTTP edge service.
- `apps/android`: Android application boundary.
- `apps/ios`: iOS application boundary.
- `infra`: local and production infrastructure definitions.

## First vertical slice acceptance criteria

- Generate two different anonymous account identities using OS entropy.
- Export signed contact cards.
- Verify valid cards and reject tampered cards.
- Enqueue opaque ciphertext to a mailbox.
- Reject duplicate envelope IDs.
- Dequeue ciphertext without interpreting it.
- Expose a gateway health endpoint once the lower-level tests pass.

## Audit posture

All cryptographic and metadata-sensitive components are treated as pre-audit. Release gates later include crypto vectors, fuzzing, replay/downgrade tests, MASVS/MASTG review, SBOM generation, dependency scanning, penetration testing and independent cryptographic review.
