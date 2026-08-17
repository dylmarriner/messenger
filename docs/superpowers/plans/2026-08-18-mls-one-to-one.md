# MLS One-to-One Vertical Slice Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a narrow, auditable MLS integration that establishes a two-device conversation, encrypts application plaintext locally, sends only serialized MLS ciphertext through the existing relay, and decrypts only on the recipient.

**Architecture:** `crates/mls-session` owns OpenMLS integration and exposes a project-level API instead of leaking OpenMLS state transitions across the application. The first provider is `OpenMlsRustCrypto` with in-memory storage for protocol integration tests only; production mobile persistence will replace the provider storage behind this boundary. MLS BasicCredential identities are random device-scoped opaque bytes, not usernames or account IDs, to avoid unnecessarily publishing the stable account identifier inside KeyPackages.

**Tech Stack:** OpenMLS 0.8.1, openmls_basic_credential 0.5.0, openmls_rust_crypto 0.5.1, openmls_traits 0.5.0, getrandom 0.4.3; ciphersuite `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`.

## Global Constraints

- Keep `content-debug` and `crypto-debug` OpenMLS features disabled.
- A KeyPackage is single-use bootstrap material and must not be designed for routine reuse.
- The MLS BasicCredential carries a random device-scoped identifier, not the user's username or stable account ID.
- Only serialized MLS ciphertext and opaque relay routing fields cross the message-relay boundary.
- No plaintext, MLS secrets, signature private keys, or key-package private material may be logged or exposed in protocol DTOs.
- The RustCrypto in-memory provider is an integration-stage provider, not the final mobile persistence design.
- Implementation remains on `scaffold/phase-1-vertical-slice` and PR #1 remains draft until execution verification is available.

---

### Task 1: Define the MLS direct-message contract

**Files:**
- Create: `crates/mls-session/Cargo.toml`
- Create: `crates/mls-session/src/lib.rs`
- Create: `crates/mls-session/tests/direct_message.rs`
- Modify: `Cargo.toml`

**Interfaces:**
- Produces: `MlsClient::generate() -> Result<MlsClient, MlsError>`
- Produces: `MlsClient::key_package() -> Result<Vec<u8>, MlsError>`
- Produces: `MlsClient::create_group() -> Result<MlsGroupState, MlsError>`
- Produces: `MlsClient::add_member(&mut MlsGroupState, &[u8]) -> Result<Vec<u8>, MlsError>` where return bytes are a serialized Welcome.
- Produces: `MlsClient::join_from_welcome(&[u8]) -> Result<MlsGroupState, MlsError>`
- Produces: `MlsClient::encrypt(&mut MlsGroupState, &[u8]) -> Result<Vec<u8>, MlsError>`
- Produces: `MlsClient::decrypt(&mut MlsGroupState, &[u8]) -> Result<Vec<u8>, MlsError>`

- [ ] Add tests that establish Alice/Bob from Bob's serialized KeyPackage and the returned Welcome.
- [ ] Assert Alice's serialized application message does not contain the plaintext byte sequence.
- [ ] Assert Bob decrypts the exact original bytes.
- [ ] Add a tamper test that flips a ciphertext byte and requires decryption failure.
- [ ] Keep `src/lib.rs` interface-empty until the tests define the desired contract.

### Task 2: Implement credential and KeyPackage generation

**Files:**
- Modify: `crates/mls-session/src/lib.rs`

- [ ] Generate a 128-bit random device credential identifier with `getrandom::fill`.
- [ ] Create an OpenMLS `BasicCredential` from only that random identifier.
- [ ] Generate and store the BasicCredential signature key pair in the provider storage.
- [ ] Build a KeyPackage using `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`.
- [ ] Serialize only the public KeyPackage for publication.
- [ ] Parse incoming KeyPackage bytes as `KeyPackageIn` and validate them before membership changes.

### Task 3: Implement two-party group establishment

**Files:**
- Modify: `crates/mls-session/src/lib.rs`

- [ ] Create groups with the selected ciphersuite, 256-byte padding, and ratchet-tree extension enabled.
- [ ] Add Bob's validated one-time KeyPackage to Alice's group.
- [ ] Merge Alice's pending add commit before returning the serialized Welcome.
- [ ] Parse the Welcome on Bob and stage/join using the matching join configuration.
- [ ] Hide `MlsGroup` behind `MlsGroupState` so callers cannot bypass project policy accidentally.

### Task 4: Implement application encryption/decryption

**Files:**
- Modify: `crates/mls-session/src/lib.rs`

- [ ] Encrypt application bytes using `MlsGroup::create_message` and serialize the resulting `MlsMessageOut`.
- [ ] Deserialize incoming bytes as `MlsMessageIn` and require conversion to a protocol message.
- [ ] Process with the recipient group and accept only `ProcessedMessageContent::ApplicationMessage`.
- [ ] Return application bytes only after MLS validation/decryption succeeds.
- [ ] Map failures to non-secret-bearing project error variants.

### Task 5: Exercise the existing opaque relay with real MLS ciphertext

**Files:**
- Create: `tests/mls_relay_vertical_slice.rs`
- Add a workspace integration-test crate only if Cargo requires one; otherwise keep the test inside `crates/mls-session/tests/relay_roundtrip.rs` with `messenger-relay` as a dev-dependency.

- [ ] Establish Alice/Bob MLS state.
- [ ] Encrypt a message on Alice.
- [ ] Put the serialized MLS bytes into `messenger_protocol::Envelope`.
- [ ] Enqueue and drain via `InMemoryRelay`.
- [ ] Decrypt only after Bob retrieves the envelope.
- [ ] Assert the relay-observed ciphertext is byte-for-byte identical to what Alice produced and contains no plaintext sequence.

### Task 6: Review gate

- [ ] Review dependency feature selection and confirm `content-debug` and `crypto-debug` are absent.
- [ ] Review all new public structs for accidental secret serialization or `Debug` exposure.
- [ ] Run `cargo fmt --check` when an execution runner is available.
- [ ] Run `cargo clippy --workspace --all-targets -- -D warnings` when an execution runner is available.
- [ ] Run `cargo test --workspace` when an execution runner is available.
- [ ] Keep PR #1 draft until those commands execute successfully.
