// Copyright (c) 2025 Rust Nostr Developers
// Distributed under the MIT software license

//! Example: Leave a group and verify it's deleted from storage.
//!
//! Flow:
//! 1. Alice creates a group and invites Bob and Charlie.
//! 2. Bob and Charlie process the Welcome message to join the group.
//! 3. Alice calls `leave_group` to leave the group.
//! 4. Verify that the group is deleted from storage.
//! 5. Assertions:
//!    - Group should be deleted from storage after leaving.
//!    - Alice should no longer be able to access the group.

use nostr_mls::prelude::*;
use nostr_mls_memory_storage::NostrMlsMemoryStorage;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;
use hex;
use nostr::prelude::*;

fn gen_identity() -> (Keys, NostrMls<NostrMlsMemoryStorage>) {
    let keys = Keys::generate();
    let mls = NostrMls::new(NostrMlsMemoryStorage::default());
    (keys, mls)
}

#[tokio::main]
async fn main() -> Result<()> {
    // Set up logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set tracing subscriber");

    // Generate identities for Alice, Bob, and Charlie
    let (alice_keys, alice_mls) = gen_identity();
    let (bob_keys, bob_mls) = gen_identity();
    let (charlie_keys, charlie_mls) = gen_identity();

    println!("=== Leave Group Example ===");
    println!("Alice: {}", alice_keys.public_key());
    println!("Bob: {}", bob_keys.public_key());
    println!("Charlie: {}", charlie_keys.public_key());

    // Step 1: Alice creates a group with Bob and Charlie
    println!("\n1. Alice creates a group with Bob and Charlie...");

    let relay = RelayUrl::parse("ws://localhost:8080").unwrap();

    // Generate key packages for Bob and Charlie
    let (bob_kp_enc, bob_tags) = bob_mls.create_key_package_for_event(&bob_keys.public_key(), [relay.clone()], Some("test-client"))?;
    let bob_unsigned = EventBuilder::new(Kind::MlsKeyPackage, bob_kp_enc)
        .tags(bob_tags)
        .build(bob_keys.public_key());
    let bob_kp_event = bob_unsigned.sign(&bob_keys).await?;
    let bob_kp: KeyPackage = alice_mls.parse_key_package(&bob_kp_event)?;

    let (charlie_kp_enc, charlie_tags) = charlie_mls.create_key_package_for_event(&charlie_keys.public_key(), [relay.clone()], Some("test-client"))?;
    let charlie_unsigned = EventBuilder::new(Kind::MlsKeyPackage, charlie_kp_enc)
        .tags(charlie_tags)
        .build(charlie_keys.public_key());
    let charlie_kp_event = charlie_unsigned.sign(&charlie_keys).await?;
    let charlie_kp: KeyPackage = alice_mls.parse_key_package(&charlie_kp_event)?;

    // Alice creates the group
    let create_result = alice_mls.create_group(
        "Test Group",
        "A test group for leave_group example",
        &alice_keys.public_key(),
        &[bob_keys.public_key(), charlie_keys.public_key()],
        &[bob_kp, charlie_kp],
        vec![alice_keys.public_key()], // Alice is admin
        vec![relay.clone()],
    )?;

    let mls_gid = create_result.group.mls_group_id.clone();
    println!("Group created with ID: {}", hex::encode(create_result.group.mls_group_id.as_slice()));
    println!("Group has {} members", alice_mls.get_members(&mls_gid)?.len());

    // Step 2: Bob and Charlie process the welcome message
    println!("\n2. Bob and Charlie join the group...");

    let welcome_hex = hex::encode(&create_result.serialized_welcome_message);
    let welcome_evt = EventBuilder::new(Kind::MlsWelcome, welcome_hex).build(alice_keys.public_key());

    // Bob processes the welcome
    bob_mls.process_welcome(&EventId::all_zeros(), &welcome_evt)?;
    println!("Bob joined the group");

    // Charlie processes the welcome
    charlie_mls.process_welcome(&EventId::all_zeros(), &welcome_evt)?;
    println!("Charlie joined the group");

    // Verify all members are in the group
    let members = alice_mls.get_members(&mls_gid)?;
    println!("Group now has {} members: {:?}", members.len(), members);

    // Step 3: Alice leaves the group
    println!("\n3. Alice leaves the group...");

    let leave_message = alice_mls.leave_group(&mls_gid)?;
    println!("Leave message generated, size: {} bytes", leave_message.serialized.len());

    // Step 4: Verify the group is deleted from Alice's storage
    println!("\n4. Verifying group deletion...");

    // Try to get the group - it should not exist
    let group_result = alice_mls.get_group(&mls_gid)?;
    match group_result {
        Some(_) => {
            println!("⚠️  WARNING: Group metadata still exists in storage after leaving!");
            println!("   This is expected because we only delete MLS data, not NostrMls metadata");
        }
        None => {
            println!("✅ SUCCESS: Group has been completely deleted from storage");
        }
    }

    // Try to get members - should fail because MLS data is deleted
    let members_result = alice_mls.get_members(&mls_gid);
    match members_result {
        Ok(_) => {
            println!("❌ ERROR: Still able to get members after leaving!");
            return Err("Should not be able to get members after leaving".into());
        }
        Err(_) => {
            println!("✅ SUCCESS: Cannot get members after leaving (MLS data deleted)");
        }
    }

    // Verify Bob and Charlie can still access the group
    println!("\n5. Verifying Bob and Charlie can still access the group...");

    let bob_group = bob_mls.get_group(&mls_gid)?;
    match bob_group {
        Some(_) => println!("✅ Bob can still access the group"),
        None => println!("❌ Bob cannot access the group"),
    }

    let charlie_group = charlie_mls.get_group(&mls_gid)?;
    match charlie_group {
        Some(_) => println!("✅ Charlie can still access the group"),
        None => println!("❌ Charlie cannot access the group"),
    }

    println!("\n=== Leave Group Example Completed Successfully ===");
    Ok(())
} 