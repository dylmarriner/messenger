#![forbid(unsafe_code)]

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{Mutex, MutexGuard},
};

use messenger_crypto_core::KeyPackageBinding;
use messenger_registration::RegisteredAccount;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishedKeyPackage {
    pub key_package: Vec<u8>,
    pub binding: KeyPackageBinding,
}

#[derive(Default)]
pub struct InMemoryKeyDirectory {
    state: Mutex<KeyDirectoryState>,
}

#[derive(Default)]
struct KeyDirectoryState {
    packages: HashMap<String, VecDeque<PublishedKeyPackage>>,
    seen_key_packages: HashSet<Vec<u8>>,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum KeyDirectoryError {
    #[error("key package binding is invalid")]
    InvalidBinding,
    #[error("key package binding does not match the registered account")]
    AccountMismatch,
    #[error("key package has already been published")]
    DuplicateKeyPackage,
    #[error("no one-time key package is available")]
    NoKeyPackage,
}

impl InMemoryKeyDirectory {
    pub fn upload(
        &self,
        account: &RegisteredAccount,
        package: PublishedKeyPackage,
    ) -> Result<(), KeyDirectoryError> {
        package
            .binding
            .verify(&package.key_package)
            .map_err(|_| KeyDirectoryError::InvalidBinding)?;

        if package.binding.account_id != account.account_id
            || package.binding.root_public_key != account.root_public_key
        {
            return Err(KeyDirectoryError::AccountMismatch);
        }

        let mut state = self.state();
        if !state.seen_key_packages.insert(package.key_package.clone()) {
            return Err(KeyDirectoryError::DuplicateKeyPackage);
        }

        state
            .packages
            .entry(account.account_id.clone())
            .or_default()
            .push_back(package);
        Ok(())
    }

    pub fn claim(&self, account_id: &str) -> Result<PublishedKeyPackage, KeyDirectoryError> {
        let mut state = self.state();
        let Some(queue) = state.packages.get_mut(account_id) else {
            return Err(KeyDirectoryError::NoKeyPackage);
        };
        let Some(package) = queue.pop_front() else {
            return Err(KeyDirectoryError::NoKeyPackage);
        };
        if queue.is_empty() {
            state.packages.remove(account_id);
        }
        Ok(package)
    }

    fn state(&self) -> MutexGuard<'_, KeyDirectoryState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}
