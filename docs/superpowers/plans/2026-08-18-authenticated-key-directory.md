# Authenticated MLS Key Directory Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bind each public MLS KeyPackage to the recipient's account-root identity so a compromised or malicious key directory cannot silently substitute its own MLS keys.

**Architecture:** Each MLS client has a random 128-bit device identifier used as its BasicCredential identity. The account-root key signs a domain-separated transcript containing that device ID and the exact serialized MLS KeyPackage bytes. The resulting public `KeyPackageBinding` travels alongside the KeyPackage. A contact verifies the binding against the root public key already authenticated by QR/contact-card exchange before calling `MlsClient::add_member`. The directory stores only signed public material and atomically consumes KeyPackages when claimed.

**Tech Stack:** Existing Ed25519 account-root key, OpenMLS 0.8.1 KeyPackages, OS CSPRNG, Axum 0.8.9. No additional hash primitive is required because Ed25519 signs the canonical serialized KeyPackage bytes directly.

## Global Constraints

- The account-root private key never leaves `AccountIdentity`.
- KeyPackage signing uses domain `messenger-key-package-binding-v1\0` and length-prefixes variable KeyPackage bytes.
- A binding contains only public/pseudonymous material: version, account ID, root public key, device ID and signature.
- The caller must verify a binding against a trusted `ContactCard`, not merely self-verify arbitrary replacement root material.
- The exact bytes that are signed are the exact bytes later parsed by OpenMLS.
- KeyPackages remain one-time material and are removed from the directory when claimed.
- Directory records never contain application plaintext, MLS private init keys, root private keys or message content.
- PR #1 remains draft until execution verification succeeds.

---

### Task 1: Expose stable random MLS device identifier

**Files:**
- Create: `crates/mls-session/tests/device_identity.rs`
- Modify: `crates/mls-session/src/lib.rs`

- [ ] Add failing test that separate MLS clients receive distinct 128-bit device IDs.
- [ ] Retain the random BasicCredential identity bytes inside `MlsClient`.
- [ ] Expose `device_id() -> [u8; 16]` without exposing signer/provider secrets.

### Task 2: Add root-signed KeyPackage binding

**Files:**
- Modify: `crates/crypto-core/tests/identity.rs`
- Modify: `crates/crypto-core/src/lib.rs`

**Interfaces:**
- Produces: `KeyPackageBinding { version, account_id, root_public_key, device_id, signature }`
- Produces: `AccountIdentity::bind_key_package(device_id: &[u8; 16], key_package: &[u8]) -> KeyPackageBinding`
- Produces: `KeyPackageBinding::verify(key_package: &[u8]) -> Result<(), CryptoError>`
- Produces: `KeyPackageBinding::verify_for_contact(contact: &ContactCard, key_package: &[u8]) -> Result<(), CryptoError>`

- [ ] Add failing tests for valid binding, package tampering, device-ID tampering and wrong contact root.
- [ ] Sign fixed-width fields plus a big-endian u32 KeyPackage length and the exact KeyPackage bytes.
- [ ] Reject KeyPackages larger than u32::MAX before transcript construction.

### Task 3: Implement one-time public key directory

**Files:**
- Create: `crates/key-directory/Cargo.toml`
- Create: `crates/key-directory/src/lib.rs`
- Create: `crates/key-directory/tests/directory.rs`
- Modify: `Cargo.toml`

- [ ] Store signed public `PublishedKeyPackage` records keyed by account ID.
- [ ] Verify binding self-signature at upload.
- [ ] Require the binding account/root key to match an already registered account record supplied by the caller.
- [ ] Atomically claim and remove one package per lookup.
- [ ] Reject duplicate serialized KeyPackages per account/device.

### Task 4: Expose key upload/claim API

**Files:**
- Modify: `services/gateway/Cargo.toml`
- Modify: `services/gateway/src/lib.rs`
- Create: `services/gateway/tests/key_directory.rs`

- [ ] Add router tests first: register account, generate MLS KeyPackage, root-sign it, upload it, claim it, verify exact bytes and binding against contact card.
- [ ] Add negative test for a substituted/tampered package.
- [ ] Encode serialized KeyPackage bytes as URL-safe base64 without padding.
- [ ] Keep package claim errors generic and rate-limit-ready.

### Task 5: E2EE trust-chain integration test

**Files:**
- Create: `crates/mls-session/tests/authenticated_directory_roundtrip.rs` or gateway-level equivalent.

- [ ] Alice authenticates Bob's claimed KeyPackage using Bob's QR/contact card root identity.
- [ ] Alice adds only the verified package to MLS.
- [ ] Alice encrypts locally, existing relay transports opaque bytes, Bob decrypts locally.
- [ ] A server-substituted KeyPackage with a different root identity is rejected before `add_member`.
