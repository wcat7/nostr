// Copyright (c) 2025 Rust Nostr Developers
// Distributed under the MIT software license

//! Example: commit_proposal flow with automatic Nostr Group-ID rotation.
//!
//! Flow:
//! 1. Alice (admin) creates a group with Bob.
//! 2. Bob calls `leave_group()` which returns a standalone Remove-Proposal message.
//! 3. Bob wraps the proposal in an encrypted Nostr event and sends it to Alice.
//! 4. Alice processes the proposal; `process_message` detects it is a *self-remove* proposal
//!    and consequently calls `commit_proposal`, which
//!      - Commits the queued proposal;
//!      - Inserts a fresh random `nostr_group_id` via GroupContextExtensions;
//!      - Returns a Commit.
//! 5. Alice merges the Commit internally; we then verify:
//!      - Group member count changes 2 → 1 (Bob removed).
//!      - `nostr_group_id` has rotated.

use nostr_mls::prelude::*;
use nostr_mls_memory_storage::NostrMlsMemoryStorage;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;
use nostr::prelude::{nip44, SecretKey, Tag, TagKind};
use hex;

fn gen_identity() -> (Keys, NostrMls<NostrMlsMemoryStorage>) {
    let keys = Keys::generate();
    let mls  = NostrMls::new(NostrMlsMemoryStorage::default());
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

    // === Bob publishes KeyPackage ===
    let relay = RelayUrl::parse("ws://localhost:8080").unwrap();

    let (bob_kp_enc, bob_tags) = bob_mls.create_key_package_for_event(&bob_keys.public_key(), [relay.clone()])?;
    let bob_kp_unsigned = EventBuilder::new(Kind::MlsKeyPackage, bob_kp_enc)
        .tags(bob_tags)
        .build(bob_keys.public_key());
    let bob_kp_event = bob_kp_unsigned.sign(&bob_keys).await?;
    let bob_kp: KeyPackage = alice_mls.parse_key_package(&bob_kp_event)?;

    // === Alice creates group with Bob ===
    let create_res = alice_mls.create_group(
        "AB Chat",
        "Alice & Bob secret room",
        &alice_keys.public_key(),
        &[bob_keys.public_key()],
        &[bob_kp.clone()],
        vec![alice_keys.public_key()],
        vec![relay.clone()],
    )?;
    let initial_gid = create_res.group.nostr_group_id;
    let mls_gid = GroupId::from_slice(create_res.group.mls_group_id.as_slice());

    // Bob processes Welcome to join
    let welcome_hex = hex::encode(&create_res.serialized_welcome_message);
    let welcome_evt = EventBuilder::new(Kind::MlsWelcome, welcome_hex).build(alice_keys.public_key());
    bob_mls.process_welcome(&EventId::all_zeros(), &welcome_evt)?;

    // === Bob initiates leave_group (Remove-Proposal) ===
    let pre_secret: group_types::GroupExporterSecret = bob_mls.exporter_secret(&mls_gid)?;
    let leave_res = bob_mls.leave_group(&mls_gid)?;

    // Wrap proposal into encrypted Nostr event (kind 448)
    let secret_key = SecretKey::from_slice(&pre_secret.secret).expect("32 bytes secret");
    let tmp_keys = Keys::new(secret_key);
    let encrypted_content = nip44::encrypt(
        tmp_keys.secret_key(),
        &tmp_keys.public_key,
        &leave_res.serialized,
        nip44::Version::default(),
    )?;
    let tag = Tag::custom(TagKind::h(), [hex::encode(initial_gid)]);
    let proposal_evt = EventBuilder::new(Kind::MlsGroupMessage, encrypted_content)
        .tag(tag)
        .sign_with_keys(&Keys::generate())?;

    // === Alice processes proposal → triggers commit_proposal ===
    let process_res = alice_mls.process_message(&proposal_evt)?;
    tracing::info!(?process_res, "Alice processed Bob's leave proposal");

    // === Assertions ===
    let new_group = alice_mls.get_group(&mls_gid)?.unwrap();
    assert_ne!(new_group.nostr_group_id, initial_gid, "Group-ID should rotate after commit_proposal");
    assert_eq!(alice_mls.get_members(&mls_gid)?.len(), 1, "Only Alice should remain in the group");

    tracing::info!("✅ commit_proposal rotation example passed");
    Ok(())
} 