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

    /// Returns a stable snapshot without changing delivery state. The caller
    /// must explicitly acknowledge delivered envelope IDs before deletion.
    pub fn retrieve_mailbox(&self, mailbox_id: &str) -> Vec<Envelope> {
        self.state()
            .mailboxes
            .get(mailbox_id)
            .map(|queue| queue.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Removes only the named envelopes from the named mailbox and returns the
    /// number of records deleted. Envelope IDs remain in the replay set.
    pub fn acknowledge(&self, mailbox_id: &str, envelope_ids: &[Uuid]) -> usize {
        if envelope_ids.is_empty() {
            return 0;
        }

        let requested: HashSet<Uuid> = envelope_ids.iter().copied().collect();
        let mut state = self.state();
        let (removed, remove_mailbox) = {
            let Some(queue) = state.mailboxes.get_mut(mailbox_id) else {
                return 0;
            };
            let before = queue.len();
            queue.retain(|envelope| !requested.contains(&envelope.envelope_id));
            (before - queue.len(), queue.is_empty())
        };

        if remove_mailbox {
            state.mailboxes.remove(mailbox_id);
        }
        removed
    }

    /// Backward-compatibility helper for early integration tests. HTTP delivery
    /// must use `retrieve_mailbox` plus explicit `acknowledge` instead.
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
