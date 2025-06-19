// Copyright (c) 2024-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! Example demonstrating how to update a group's `NostrGroupDataExtension` using
//! `update_group_data`.
//!
//! This example closely follows the flow of `examples/mls_memory.rs` but adds an
//! extra step where the group administrator updates the group metadata (name,
//! description, relay list, etc.) after the group has been created.

use nostr_mls::prelude::*;
use nostr_mls_memory_storage::NostrMlsMemoryStorage;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;
use hex;

fn generate_identity() -> (Keys, NostrMls<NostrMlsMemoryStorage>) {
    let keys = Keys::generate();
    let nostr_mls = NostrMls::new(NostrMlsMemoryStorage::default());
    (keys, nostr_mls)
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialise logger
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");

    let relay_url = RelayUrl::parse("ws://localhost:8080").unwrap();

    // === Generate identities ===
    let (alice_keys, alice_nostr_mls) = generate_identity();
    let (bob_keys, bob_nostr_mls) = generate_identity();

    // === Bob publishes his KeyPackage (simulated) ===
    let (bob_key_package_encoded, tags) = bob_nostr_mls
        .create_key_package_for_event(&bob_keys.public_key(), [relay_url.clone()])?;

    let bob_key_package_event = EventBuilder::new(Kind::MlsKeyPackage, bob_key_package_encoded)
        .tags(tags)
        .build(bob_keys.public_key())
        .sign(&bob_keys)
        .await?;

    let bob_key_package: KeyPackage = alice_nostr_mls.parse_key_package(&bob_key_package_event)?;

    // === Alice creates the group (Alice is the creator & admin) ===
    let create_res = alice_nostr_mls.create_group(
        "Original Name",
        "A secret chat between Bob and Alice",
        &alice_keys.public_key(),
        &[bob_keys.public_key()],
        &[bob_key_package],
        vec![alice_keys.public_key()],
        vec![relay_url.clone()],
    )?;
    let group_id = GroupId::from_slice(create_res.group.mls_group_id.as_slice());

    // === Alice sends Welcome to Bob (simulated locally) ===
    let serialized_welcome = create_res.serialized_welcome_message.clone();
    let welcome_event = EventBuilder::new(Kind::MlsWelcome, hex::encode(serialized_welcome))
        .build(alice_keys.public_key());

    let welcome = bob_nostr_mls.process_welcome(&EventId::all_zeros(), &welcome_event)?;
    bob_nostr_mls.accept_welcome(&welcome)?;

    tracing::info!("Group created with name: {}", create_res.group.name);

    // === Alice updates the group metadata ===
    let new_name = "Bob & Alice – Updated".to_string();
    let new_description = "Now with an updated description".to_string();
    let new_relays = vec![RelayUrl::parse("ws://localhost:9090").unwrap()];

    let commit_message = alice_nostr_mls.update_group_data(
        &group_id,
        Some(new_name.clone()),
        Some(new_description.clone()),
        None, // keep same admin list
        Some(new_relays.clone()),
    )?;

    tracing::info!("Generated commit message ({} bytes)", commit_message.serialized.len());

    // After merging locally, the stored group should reflect the new metadata.
    let updated_group = alice_nostr_mls
        .get_group(&group_id)?
        .expect("Group should exist");

    assert_eq!(&updated_group.name, &new_name);
    assert_eq!(&updated_group.description, &new_description);

    tracing::info!("Group metadata updated successfully:");
    tracing::info!("  Name: {}", updated_group.name);
    tracing::info!("  Description: {}", updated_group.description);
    tracing::info!("  Relays: {:?}", alice_nostr_mls.get_relays(&group_id)?);

    // === Bob receives the commit and processes it ===
    let mut bob_group = bob_nostr_mls
        .load_mls_group(&group_id)?
        .expect("Bob should have the MLS group after welcome");

    bob_nostr_mls.process_message_for_group(&mut bob_group, commit_message.as_bytes())?;

    // Verify Bob's view is updated
    let updated_ext = NostrGroupDataExtension::from_group(&bob_group)?;
    assert_eq!(updated_ext.name, new_name);
    assert_eq!(updated_ext.description, new_description);
    assert!(updated_ext.relays.contains(&new_relays[0]));

    tracing::info!("Bob successfully processed commit & updated metadata");

    // In a real application, Alice would now wrap `commit_message.serialized`
    // into an appropriate Nostr event (kind 448) and send it to the other
    // members so they can apply the same commit.

    Ok(())
} 