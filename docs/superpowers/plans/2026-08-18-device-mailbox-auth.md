# Device Mailbox Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add account-authorized device identities, short-lived device sessions, authenticated mailbox retrieval/acknowledgement, and anonymous ciphertext submission without using the account-root key for routine messaging operations.

**Architecture:** Each installation generates an independent Ed25519 device-auth key, random 128-bit device ID, and random 256-bit mailbox ID. The account-root key signs a public `DeviceCertificate` binding those values to the pseudonymous account. The backend verifies and stores only the public certificate. Device login is challenge-response using the device-auth key; successful proof issues a random 256-bit 15-minute bearer token whose SHA-256 digest is stored server-side. Message submission remains sender-anonymous in this slice; mailbox reads and ACKs require the device session. MLS uses the same device ID as the certificate so KeyPackage bindings, routing identity, and device revocation refer to one device.

**Tech Stack:** Ed25519-dalek 3.0.0, getrandom 0.4.3, SHA-2 0.11.0, Axum 0.8.9, UUID 1.24.0, OpenMLS 0.8.1. Session-token hashing uses SHA-256; raw bearer tokens are returned once and are never stored by the server.

## Global Constraints

- Account-root signing keys are used only for account/device authorization operations, never routine mailbox authentication.
- `DeviceIdentity` must not implement `Serialize`, `Debug`, or expose its private device-auth key.
- Device certificate signature domain is `messenger-device-certificate-v1\0`.
- Device-auth proof domain is `messenger-device-auth-v1\0` and binds challenge ID, challenge bytes, device ID, and mailbox ID.
- Device IDs are 128-bit OS-random values and mailbox IDs are 256-bit OS-random values.
- Mailbox identifiers are routing pseudonyms, not account IDs.
- Device-auth challenges are one-time, 256-bit, and expire after two minutes.
- Device sessions expire after 15 minutes. Server state stores SHA-256(token), never the raw bearer token.
- Device revocation invalidates all sessions for that device.
- Anonymous message submission must never require or expose the sender account ID in the envelope.
- Mailbox retrieval is non-destructive. Envelopes are removed only by authenticated acknowledgement.
- Relay ciphertext remains an opaque byte vector and must never be parsed or logged by the backend.
- Production persistence, Privacy Pass send authorization, IP-relay transport, and push wakeups remain later tasks behind these interfaces.
- PR #1 remains draft until workspace tests actually execute successfully.

---

### Task 1: Device identity and account-root authorization

**Files:**
- Modify: `crates/crypto-core/tests/identity.rs`
- Modify: `crates/crypto-core/src/lib.rs`

**Interfaces:**
- Produces: `DeviceIdentity::generate() -> Result<DeviceIdentity, CryptoError>`
- Produces: `DeviceIdentity::device_id() -> [u8; 16]`
- Produces: `DeviceIdentity::mailbox_id() -> &str`
- Produces: `AccountIdentity::authorize_device(&DeviceIdentity) -> DeviceCertificate`
- Produces: `DeviceCertificate::verify() -> Result<(), CryptoError>`
- Produces: `DeviceIdentity::authentication_proof(challenge_id: &[u8;16], challenge: &[u8;32]) -> DeviceAuthProof`
- Produces: `DeviceAuthProof::verify(certificate: &DeviceCertificate, challenge_id: &[u8;16], challenge: &[u8;32]) -> Result<(), CryptoError>`

- [ ] Add failing tests for unique device/mailbox IDs, certificate verification, certificate-field tampering, valid device proof and challenge/proof tampering.
- [ ] Generate device-auth secret using OS CSPRNG inside `Zeroizing` before constructing `SigningKey`.
- [ ] Root-sign deterministic fixed-width certificate fields.
- [ ] Verify device-auth proofs strictly using the public device-auth key from the root-signed certificate.

### Task 2: Make MLS consume the authorized device ID

**Files:**
- Modify: `crates/mls-session/tests/device_identity.rs`
- Modify: `crates/mls-session/src/lib.rs`

- [ ] Add failing test proving `MlsClient::generate_for_device(device_id)` uses exactly the certificate device ID as its BasicCredential identity.
- [ ] Keep `MlsClient::generate()` as a convenience wrapper for tests.
- [ ] Add `generate_for_device([u8;16])` and use the supplied bytes as the BasicCredential identity.

### Task 3: Device registry and short-lived sessions

**Files:**
- Create: `crates/device-service/Cargo.toml`
- Create: `crates/device-service/src/lib.rs`
- Create: `crates/device-service/tests/device_auth.rs`
- Modify: `Cargo.toml`

**Interfaces:**
- Produces: `RegisteredDevice { certificate }`
- Produces: `DeviceAuthChallenge { id: Uuid, bytes: [u8;32], device_id: String }`
- Produces: `IssuedDeviceSession { token: [u8;32], expires_in: Duration }`
- Produces: `InMemoryDeviceService::register_device(account, certificate)`
- Produces: `issue_challenge(device_id)`
- Produces: `authenticate(challenge_id, proof)`
- Produces: `authorize_session(token)`
- Produces: `device(device_id)` and `device_by_mailbox(mailbox_id)`
- Produces: `revoke_device(device_id)`

- [ ] Register only certificates whose root identity matches an existing registered account.
- [ ] Consume auth challenges before signature verification.
- [ ] Generate 256-bit bearer tokens from the OS CSPRNG.
- [ ] Store only SHA-256 token digests and expiry/device mapping.
- [ ] Reject expired sessions and invalidate sessions after device revocation.

### Task 4: Non-destructive relay retrieval and acknowledgement

**Files:**
- Modify: `crates/relay/tests/relay.rs`
- Modify: `crates/relay/src/lib.rs`

**Interfaces:**
- Produces: `retrieve_mailbox(&str) -> Vec<Envelope>`
- Produces: `acknowledge(&str, &[Uuid]) -> usize`

- [ ] Add failing test proving retrieval does not delete ciphertext.
- [ ] Add failing test proving only explicitly acknowledged envelope IDs are removed.
- [ ] Preserve permanent duplicate-envelope-ID rejection for the in-memory process lifetime.
- [ ] Keep `drain_mailbox` only as a test/backward-compatibility helper during migration, not for HTTP delivery.

### Task 5: Device, session, relay and ACK HTTP APIs

**Files:**
- Modify: `services/gateway/Cargo.toml`
- Modify: `services/gateway/src/lib.rs`
- Create: `services/gateway/tests/mailbox.rs`
- Modify: `services/gateway/tests/key_directory.rs`

**Endpoints:**
- `POST /v1/devices`
- `POST /v1/device-auth/challenge`
- `POST /v1/device-auth/session`
- `POST /v1/envelopes`
- `GET /v1/mailbox`
- `POST /v1/mailbox/ack`

- [ ] Register a root-signed device certificate only after anonymous account registration.
- [ ] Issue and verify device-auth challenges, returning a short-lived bearer token once.
- [ ] Accept anonymous ciphertext submission with no sender account field.
- [ ] Require `Authorization: Bearer <token>` for mailbox retrieval and acknowledgement.
- [ ] Determine the mailbox exclusively from the authorized session; never accept a mailbox ID parameter on authenticated retrieval/ACK.
- [ ] Return KeyPackage claim responses with the registered root-signed `DeviceCertificate` so senders can authenticate both the claimed MLS KeyPackage and its destination mailbox against the trusted contact root.
- [ ] Reject KeyPackage upload if its binding device ID does not match a registered device certificate for that account.
- [ ] ACK only IDs belonging to the authorized device mailbox.

### Task 6: Full authenticated transport integration test

**Files:**
- Create: `services/gateway/tests/full_vertical_slice.rs`

- [ ] Register Bob anonymously.
- [ ] Generate and root-authorize Bob's device.
- [ ] Create Bob MLS state using the same device ID.
- [ ] Upload root-authenticated Bob KeyPackage.
- [ ] Alice claims the package and device certificate, verifies both against Bob's QR/contact card, and establishes MLS.
- [ ] Alice locally encrypts a message and submits only opaque ciphertext to Bob's mailbox.
- [ ] Bob authenticates with his device key and receives the ciphertext through `/v1/mailbox`.
- [ ] Bob decrypts locally, sends an authenticated ACK, and confirms a subsequent mailbox read is empty.
- [ ] Verify an invalid/stolen session token cannot retrieve or acknowledge Bob's mailbox.

### Task 7: Review gate

- [ ] Confirm no account-root private key is used by any routine relay endpoint.
- [ ] Confirm no raw session token is persisted server-side.
- [ ] Confirm sender account identity is absent from the relay submit DTO.
- [ ] Confirm mailbox reads are non-destructive until explicit ACK.
- [ ] Run fmt, clippy and workspace tests when a runner is available and keep PR draft until then.
