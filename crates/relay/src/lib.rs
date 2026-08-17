#![forbid(unsafe_code)]

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{Mutex, MutexGuard},
};

use messenger_protocol::Envelope;
use thiserror::Error;
use uuid::Uuid;

#[derive(Default)]
pub struct InMemoryRelay {
    inner: Mutex<RelayState>,
}

#[derive(Default)]
struct RelayState {
    seen_envelope_ids: HashSet<Uuid>,
    mailboxes: HashMap<String, VecDeque<Envelope>>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RelayError {
    #[error("duplicate envelope id {0}")]
    DuplicateEnvelope(Uuid),
}

impl InMemoryRelay {
    pub fn enqueue(&self, envelope: Envelope) -> Result<(), RelayError> {
        let mut state = self.state();

        if !state.seen_envelope_ids.insert(envelope.envelope_id) {
            return Err(RelayError::DuplicateEnvelope(envelope.envelope_id));
        }

        state
            .mailboxes
            .entry(envelope.mailbox_id.clone())
            .or_default()
            .push_back(envelope);

        Ok(())
    }

    pub fn drain_mailbox(&self, mailbox_id: &str) -> Vec<Envelope> {
        self.state()
            .mailboxes
            .remove(mailbox_id)
            .map(VecDeque::into_iter)
            .into_iter()
            .flatten()
            .collect()
    }

    fn state(&self) -> MutexGuard<'_, RelayState> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}
