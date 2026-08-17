#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const ENVELOPE_VERSION: u8 = 1;

/// Server-visible delivery envelope.
///
/// `ciphertext` is intentionally an opaque byte vector. This crate contains no
/// message-content parser and no cryptographic private-key dependency.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub version: u8,
    pub envelope_id: Uuid,
    pub mailbox_id: String,
    pub ciphertext: Vec<u8>,
}
