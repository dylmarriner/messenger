# Foundation Vertical Slice Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish a testable monorepo foundation with real anonymous account-root identity/contact-card cryptography and an opaque message-relay contract.

**Architecture:** Security-sensitive behavior lives in small Rust crates with explicit interfaces. Native clients consume the crypto core through a later narrow FFI layer; the backend consumes protocol types and relay interfaces but never the crypto private-key implementation.

**Tech Stack:** Rust 1.97.1, edition 2024, Ed25519, OS CSPRNG, Axum 0.8.9, Tokio 1.53.1, Serde 1.0.229, UUID 1.24.0; OpenMLS 0.8.1 is reserved for the next E2EE task.

## Global Constraints

- No phone number or email is required for account creation.
- No private account-root key may be serialized into an API DTO.
- No placeholder cryptography.
- Server-visible relay envelopes contain opaque ciphertext only.
- Security-sensitive dependency versions are pinned.
- Implementation occurs on `scaffold/phase-1-vertical-slice`, not `main`.

---

### Task 1: Anonymous identity and signed contact card

**Files:**
- Test: `crates/crypto-core/tests/identity.rs`
- Create: `crates/crypto-core/src/lib.rs`

**Interfaces:**
- Produces: `AccountIdentity::generate() -> Result<AccountIdentity, CryptoError>`
- Produces: `AccountIdentity::account_id() -> &str`
- Produces: `AccountIdentity::contact_card() -> ContactCard`
- Produces: `ContactCard::verify() -> Result<(), CryptoError>`

- [ ] Write tests proving identities are unique, valid cards verify, and modified account IDs fail verification.
- [ ] Run `cargo test -p messenger-crypto-core` and verify RED because the interface is absent.
- [ ] Implement account ID generation from 128 bits of OS entropy and Ed25519 signing from 256 bits of OS entropy.
- [ ] Sign `b"messenger-contact-card-v1\0" || account_id_raw || root_public_key`.
- [ ] Run `cargo test -p messenger-crypto-core` and verify GREEN.

### Task 2: Opaque relay

**Files:**
- Test: `crates/relay/tests/relay.rs`
- Create: `crates/protocol/src/lib.rs`
- Create: `crates/relay/src/lib.rs`

**Interfaces:**
- Produces: `Envelope { version, envelope_id, mailbox_id, ciphertext }`
- Produces: `InMemoryRelay::enqueue(Envelope) -> Result<(), RelayError>`
- Produces: `InMemoryRelay::drain_mailbox(&str) -> Vec<Envelope>`

- [ ] Write tests proving ciphertext round-trips unchanged and duplicate IDs are rejected.
- [ ] Run `cargo test -p messenger-relay` and verify RED.
- [ ] Implement protocol DTO and relay without ciphertext parsing.
- [ ] Run `cargo test -p messenger-relay` and verify GREEN.

### Task 3: HTTP gateway shell

**Files:**
- Create: `services/gateway/src/main.rs`

**Interfaces:**
- Produces: `GET /health -> 200 {"status":"ok"}`

- [ ] Add a router test before adding the route.
- [ ] Verify the test fails.
- [ ] Implement the Axum health route and bind using `MESSENGER_BIND`, defaulting to `127.0.0.1:8080` only for development.
- [ ] Run gateway tests and verify GREEN.

### Task 4: Repository and infrastructure scaffold

**Files:**
- Create: `.github/workflows/ci.yml`
- Create: `docker-compose.yml`
- Create: `apps/android/README.md`
- Create: `apps/ios/README.md`
- Create: `infra/README.md`

- [ ] Add CI for fmt, clippy and workspace tests.
- [ ] Add local PostgreSQL, Redis, NATS and MinIO services without embedding production secrets.
- [ ] Document the native client boundaries and next generation steps.
- [ ] Verify no secret values are committed.

### Task 5: Review gate

- [ ] Run `cargo fmt --check`.
- [ ] Run `cargo clippy --workspace --all-targets -- -D warnings`.
- [ ] Run `cargo test --workspace`.
- [ ] Review diff for private-key serialization, plaintext logging and accidental message parsing.
- [ ] Open a PR to `main`; do not merge until CI is green.
