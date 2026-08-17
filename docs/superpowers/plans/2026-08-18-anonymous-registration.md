# Anonymous Registration Vertical Slice Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement anonymous account registration where the backend verifies possession of the client-generated account-root private key without collecting phone numbers, email addresses, or any real-world identity.

**Architecture:** The client requests a short-lived random registration challenge, signs a domain-separated binary transcript with its account-root Ed25519 key, and submits only the public proof. `crates/registration` owns one-time challenge lifecycle and pseudonymous account records; `crates/crypto-core` owns proof generation/verification; the Axum gateway exposes the versioned REST flow. Challenges are stored only in memory in this vertical slice and are consumed on first registration attempt. Production persistence/rate limiting follows behind the same service interface.

**Tech Stack:** Ed25519-dalek 3.0.0, getrandom 0.4.3, UUID 1.24.0, Axum 0.8.9, Tokio 1.53.1, Serde 1.0.229, base64url without padding.

## Global Constraints

- Registration requires no phone number, email address, contact upload, real name, SIM identity, or device attestation.
- The account-root private key never leaves `AccountIdentity` and is never serializable or debug-printable.
- A valid registration requires possession of the account-root private key, not merely possession of a copied public contact card.
- Registration signatures are domain-separated with `messenger-registration-v1\0`.
- Registration signs challenge ID, challenge bytes, raw account ID, and root public key.
- Challenges are 256 bits from the OS CSPRNG, addressed by random UUIDv4 IDs, expire after five minutes, and are one-time-use.
- Failed proof attempts consume the referenced challenge to prevent repeated oracle use.
- Server account records contain only pseudonymous account ID, account-root public key, and status required for operation.
- No request or error path logs registration signatures, challenge bytes, private keys, recovery data, or message content.
- PR #1 remains draft until workspace execution verification is available.

---

### Task 1: Define registration proof cryptography

**Files:**
- Modify: `crates/crypto-core/tests/identity.rs`
- Modify: `crates/crypto-core/src/lib.rs`

**Interfaces:**
- Produces: `RegistrationProof { version, account_id, root_public_key, signature }`
- Produces: `AccountIdentity::registration_proof(challenge_id: &[u8; 16], challenge: &[u8; 32]) -> RegistrationProof`
- Produces: `RegistrationProof::verify(challenge_id: &[u8; 16], challenge: &[u8; 32]) -> Result<(), CryptoError>`

- [ ] Add failing tests proving a valid proof verifies.
- [ ] Add failing tests proving a changed challenge, challenge ID, account ID, or root public key invalidates the proof.
- [ ] Implement deterministic binary transcript signing without JSON canonicalization.
- [ ] Reuse strict Ed25519 verification.

### Task 2: Implement one-time registration challenge service

**Files:**
- Create: `crates/registration/Cargo.toml`
- Create: `crates/registration/src/lib.rs`
- Create: `crates/registration/tests/registration.rs`
- Modify: `Cargo.toml`

**Interfaces:**
- Produces: `RegistrationChallenge { id: Uuid, bytes: [u8; 32] }`
- Produces: `RegisteredAccount { account_id, root_public_key }`
- Produces: `InMemoryRegistrationService::new(ttl: Duration) -> Self`
- Produces: `issue_challenge() -> Result<RegistrationChallenge, RegistrationError>`
- Produces: `register(challenge_id: Uuid, proof: RegistrationProof) -> Result<RegisteredAccount, RegistrationError>`
- Produces: `account(account_id: &str) -> Option<RegisteredAccount>`

- [ ] Add tests for successful registration and account lookup.
- [ ] Add test proving a challenge cannot be replayed.
- [ ] Add test proving an expired challenge is rejected.
- [ ] Add test proving invalid proof is rejected and consumes the challenge.
- [ ] Store only public account material after successful registration.

### Task 3: Expose versioned HTTP registration endpoints

**Files:**
- Modify: `services/gateway/Cargo.toml`
- Modify: `services/gateway/src/lib.rs`
- Create: `services/gateway/tests/registration.rs`

**Interfaces:**
- Produces: `POST /v1/registration/challenge -> 201`
- Produces: `POST /v1/registration -> 201`

- [ ] Add end-to-end router test before endpoint implementation.
- [ ] Decode challenge response, sign it using a locally generated `AccountIdentity`, submit the proof, and assert registration succeeds.
- [ ] Add negative router test for a modified registration proof.
- [ ] Encode challenge bytes as URL-safe base64 without padding.
- [ ] Return generic authentication failures without cryptographic internals.

### Task 4: Security review gate

- [ ] Verify the gateway state owns only the registration service, never an account-root private key.
- [ ] Verify challenge material is deleted after the first registration attempt.
- [ ] Verify all externally supplied strings and byte arrays are length/format checked before signature verification.
- [ ] Verify no plaintext or private secret logging was introduced.
- [ ] Run fmt, clippy and workspace tests when a runner is available; keep PR draft until then.
