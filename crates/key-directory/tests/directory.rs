use messenger_crypto_core::AccountIdentity;
use messenger_key_directory::{InMemoryKeyDirectory, KeyDirectoryError, PublishedKeyPackage};
use messenger_registration::RegisteredAccount;

fn account(identity: &AccountIdentity) -> RegisteredAccount {
    let card = identity.contact_card();
    RegisteredAccount {
        account_id: card.account_id,
        root_public_key: card.root_public_key,
    }
}

#[test]
fn signed_key_package_can_be_uploaded_and_claimed_once() {
    let directory = InMemoryKeyDirectory::default();
    let identity = AccountIdentity::generate().expect("identity");
    let account = account(&identity);
    let key_package = b"one-time-openmls-key-package".to_vec();
    let binding = identity
        .bind_key_package(&[0x11_u8; 16], &key_package)
        .expect("binding");
    let published = PublishedKeyPackage {
        key_package,
        binding,
    };

    directory
        .upload(&account, published.clone())
        .expect("upload");
    assert_eq!(
        directory.claim(&account.account_id).expect("claim"),
        published
    );
    assert_eq!(
        directory.claim(&account.account_id),
        Err(KeyDirectoryError::NoKeyPackage)
    );
}

#[test]
fn directory_rejects_tampered_or_wrong_account_packages() {
    let directory = InMemoryKeyDirectory::default();
    let identity = AccountIdentity::generate().expect("identity");
    let other_identity = AccountIdentity::generate().expect("other identity");
    let key_package = b"signed-package".to_vec();
    let binding = identity
        .bind_key_package(&[0x22_u8; 16], &key_package)
        .expect("binding");

    let mut tampered = key_package.clone();
    tampered[0] ^= 0x01;
    assert_eq!(
        directory.upload(
            &account(&identity),
            PublishedKeyPackage {
                key_package: tampered,
                binding: binding.clone(),
            },
        ),
        Err(KeyDirectoryError::InvalidBinding)
    );

    assert_eq!(
        directory.upload(
            &account(&other_identity),
            PublishedKeyPackage {
                key_package,
                binding,
            },
        ),
        Err(KeyDirectoryError::AccountMismatch)
    );
}

#[test]
fn consumed_or_queued_key_package_cannot_be_uploaded_again() {
    let directory = InMemoryKeyDirectory::default();
    let identity = AccountIdentity::generate().expect("identity");
    let account = account(&identity);
    let key_package = b"never-reuse-this-key-package".to_vec();
    let published = PublishedKeyPackage {
        binding: identity
            .bind_key_package(&[0x33_u8; 16], &key_package)
            .expect("binding"),
        key_package,
    };

    directory
        .upload(&account, published.clone())
        .expect("first upload");
    assert_eq!(
        directory.upload(&account, published.clone()),
        Err(KeyDirectoryError::DuplicateKeyPackage)
    );

    directory.claim(&account.account_id).expect("consume package");
    assert_eq!(
        directory.upload(&account, published),
        Err(KeyDirectoryError::DuplicateKeyPackage)
    );
}
