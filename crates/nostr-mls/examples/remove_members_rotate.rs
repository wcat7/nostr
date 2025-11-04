// Copyright (c) 2025 Rust Nostr Developers
// Distributed under the MIT software license

//! Example: single-commit member removal with automatic Nostr Group-ID rotation.
//!
//! Flow:
//! 1. Alice creates a group and invites Bob and Charlie.
//! 2. Bob and Charlie process the Welcome message to join the group.
//! 3. Alice calls `remove_members` to remove Charlie:
//!    - The resulting single Commit includes the Remove proposal and a GroupContextExtensions proposal with a freshly generated group-id.
//! 4. Bob processes the Commit and synchronizes the new group-id and member list.
//! 5. Assertions:
//!    - Member count changes from 3 → 2.
//!    - `nostr_group_id` has rotated.

use nostr_mls::prelude::*;
use nostr_mls_memory_storage::NostrMlsMemoryStorage;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;
use hex;
use nostr::prelude::{nip44, SecretKey, Tag, TagKind};

fn gen_identity() -> (Keys, NostrMls<NostrMlsMemoryStorage>) {
    let keys = Keys::generate();
    let mls = NostrMls::new(NostrMlsMemoryStorage::default());
    (keys, mls)
}

#[tokio::main]
async fn main() -> Result<()> {
    // === Logging ===
    let subscriber = FmtSubscriber::builder().with_max_level(Level::INFO).finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    // === Identities ===
    let (alice_keys, alice_mls) = gen_identity();
    let (bob_keys,   bob_mls)   = gen_identity();
    let (charlie_keys, charlie_mls) = gen_identity();

    // === Publish KeyPackages for Bob & Charlie ===
    let relay = RelayUrl::parse("ws://localhost:8080").unwrap();

    // Bob
    let (bob_kp_enc, bob_tags) = bob_mls.create_key_package_for_event(&bob_keys.public_key(), [relay.clone()], None)?;
    let bob_unsigned = EventBuilder::new(Kind::MlsKeyPackage, bob_kp_enc)
        .tags(bob_tags)
        .build(bob_keys.public_key());
    let bob_kp_event = bob_unsigned.sign(&bob_keys).await?;
    let bob_kp: KeyPackage = alice_mls.parse_key_package(&bob_kp_event)?;

    // Charlie
    let (charlie_kp_enc, charlie_tags) = charlie_mls.create_key_package_for_event(&charlie_keys.public_key(), [relay.clone()], None)?;
    let charlie_unsigned = EventBuilder::new(Kind::MlsKeyPackage, charlie_kp_enc)
        .tags(charlie_tags)
        .build(charlie_keys.public_key());
    let charlie_kp_event = charlie_unsigned.sign(&charlie_keys).await?;
    let charlie_kp: KeyPackage = alice_mls.parse_key_package(&charlie_kp_event)?;

    // === Alice creates group with Bob & Charlie ===
    let create_res = alice_mls.create_group(
        "ABC Chat",
        "Secret room",
        &alice_keys.public_key(),
        &[bob_keys.public_key(), charlie_keys.public_key()],
        &[bob_kp.clone(), charlie_kp.clone()],
        vec![alice_keys.public_key()],
        vec![relay.clone()],
    )?;
    let initial_group_id = create_res.group.nostr_group_id;
    let mls_gid = GroupId::from_slice(create_res.group.mls_group_id.as_slice());

    // === Bob & Charlie process Welcome ===
    let welcome_hex = hex::encode(&create_res.serialized_welcome_message);
    let welcome_evt = EventBuilder::new(Kind::MlsWelcome, welcome_hex).build(alice_keys.public_key());
    bob_mls.process_welcome(&EventId::all_zeros(), &welcome_evt)?;
    charlie_mls.process_welcome(&EventId::all_zeros(), &welcome_evt)?;

    // === Alice removes Charlie (single commit) ===
    let pre_secret = alice_mls.exporter_secret(&mls_gid)?;

    let remove_res = alice_mls.remove_members(&mls_gid, &[charlie_keys.public_key().to_string()])?;

    // === Build the NIP-44 encrypted commit event using the old exporter secret and the previous group-id tag ===
    let secret_key = SecretKey::from_slice(&pre_secret.secret).expect("32 bytes secret");
    let tmp_keys = Keys::new(secret_key);
    let encrypted_content = nip44::encrypt(
        tmp_keys.secret_key(),
        &tmp_keys.public_key,
        &remove_res.serialized,
        nip44::Version::default(),
    )?;

    let tag = Tag::custom(TagKind::h(), [hex::encode(initial_group_id)]);
    let commit_evt = EventBuilder::new(Kind::MlsGroupMessage, encrypted_content)
        .tag(tag)
        .sign_with_keys(&Keys::generate())?;

    // Bob processes the Commit
    bob_mls.process_message(&commit_evt)?;

    // === Assertions ===
    let new_group_alice = alice_mls.get_group(&mls_gid)?.unwrap();
    assert_ne!(new_group_alice.nostr_group_id, initial_group_id, "Group-ID should rotate after removeMembers");
    assert_eq!(alice_mls.get_members(&mls_gid)?.len(), 2);

    let new_group_bob = bob_mls.get_group(&mls_gid)?.unwrap();
    assert_eq!(new_group_bob.nostr_group_id, new_group_alice.nostr_group_id);
    assert_eq!(bob_mls.get_members(&mls_gid)?.len(), 2);

    tracing::info!("✅ remove_members single-commit rotation example passed");
    Ok(())
} 