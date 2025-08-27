// Copyright (c) 2024-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! Example demonstrating deferred commit processing:
//! 1. Alice creates a group and invites Bob
//! 2. Bob joins via welcome
//! 3. Alice sends a regular message
//! 4. Alice updates group name (generates commit)
//! 5. Bob processes both messages with deferred commit handling
//! 6. Bob manually processes the commit to update group name

use nostr_mls::prelude::*;
use nostr_mls_memory_storage::NostrMlsMemoryStorage;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;
use hex;
use nostr::prelude::{nip44, SecretKey, Tag, TagKind};

fn generate_identity() -> (Keys, NostrMls<NostrMlsMemoryStorage>) {
    let keys = Keys::generate();
    let nostr_mls = NostrMls::new(NostrMlsMemoryStorage::default());
    (keys, nostr_mls)
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logger
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");

    let relay_url = RelayUrl::parse("ws://localhost:8080").unwrap();

    // === Generate identities ===
    let (alice_keys, alice_nostr_mls) = generate_identity();
    let (bob_keys, bob_nostr_mls) = generate_identity();

    tracing::info!("=== Starting deferred commit processing test ===");

    // === Bob publishes his KeyPackage ===
    let (bob_key_package_encoded, tags) = bob_nostr_mls
        .create_key_package_for_event(&bob_keys.public_key(), [relay_url.clone()], "test-client")?;

    let bob_key_package_event = EventBuilder::new(Kind::MlsKeyPackage, bob_key_package_encoded)
        .tags(tags)
        .build(bob_keys.public_key())
        .sign(&bob_keys)
        .await?;

    let bob_key_package: KeyPackage = alice_nostr_mls.parse_key_package(&bob_key_package_event)?;

    // === Alice creates the group ===
    tracing::info!("Step 1: Alice creates group with Bob");
    let create_res = alice_nostr_mls.create_group(
        "Original Group Name",
        "A test group for deferred commit processing",
        &alice_keys.public_key(),
        &[bob_keys.public_key()],
        &[bob_key_package],
        vec![alice_keys.public_key()],
        vec![relay_url.clone()],
    )?;
    
    let group_id = GroupId::from_slice(create_res.group.mls_group_id.as_slice());
    let nostr_group_id = create_res.group.nostr_group_id.clone();
    
    tracing::info!("Group created with ID: {:?}", nostr_group_id);
    tracing::info!("Group name: {}", create_res.group.name);

    // === Bob joins via welcome ===
    tracing::info!("Step 2: Bob joins the group");
    let serialized_welcome = create_res.serialized_welcome_message.clone();
    let welcome_event = EventBuilder::new(Kind::MlsWelcome, hex::encode(serialized_welcome))
        .build(alice_keys.public_key());

    let welcome = bob_nostr_mls.process_welcome(&EventId::all_zeros(), &welcome_event)?;
    bob_nostr_mls.accept_welcome(&welcome)?;
    
    // Verify Bob joined
    let bob_groups = bob_nostr_mls.get_groups()?;
    let bob_group = bob_groups.first().unwrap();
    tracing::info!("Bob joined group: {}", bob_group.name);

    // === Step 3: Alice sends a regular message ===
    tracing::info!("Step 3: Alice sends a regular message (skipped for now)");
    // Skip regular message test for now to focus on commit processing
    tracing::info!("Regular message test skipped - focusing on commit processing");

    // === Step 4: Generate and save pre-secret before updating group ===
    tracing::info!("Step 4: Generate and save pre-secret before updating group");
    
    // Get the group's exporter secret BEFORE updating group data
    let pre_secret = alice_nostr_mls.exporter_secret(&group_id)?;
    let secret_key = pre_secret.secret;
    
    tracing::info!("Generated pre-secret ({} bytes)", secret_key.len());
    
    // === Step 5: Alice updates group name (generates commit) ===
    tracing::info!("Step 5: Alice updates group name");
    let new_name = "Updated Group Name - Deferred Processing Test".to_string();
    let new_description = "Group name updated via deferred commit processing".to_string();
    
    let commit_message = alice_nostr_mls.update_group_data(
        &group_id,
        Some(new_name.clone()),
        Some(new_description.clone()),
        None, // keep same admin list
        None, // keep same relays
    )?;

    tracing::info!("Generated commit message ({} bytes)", commit_message.serialized.len());

    // === Step 6: Create commit proposal message event ===
    tracing::info!("Step 6: Create commit proposal message event");
    
    // Create the commit proposal message event
    let commit_event = alice_nostr_mls.create_commit_proposal_message(
        hex::encode(nostr_group_id.clone()),
        &commit_message.serialized,
        &secret_key,
    )?;
    
    tracing::info!("Created commit event with ID: {}", commit_event.id);

    // === Step 7: Bob processes the commit event with deferred handling ===
    tracing::info!("Step 7: Bob processes commit event with deferred handling");
    
    // Process the commit event - this should return message_bytes for deferred processing
    let commit_result = bob_nostr_mls.process_message(&commit_event)?;
    
    tracing::info!("Commit event processed with deferred handling:");
    tracing::info!("  Message: {:?}", commit_result.message.is_some());
    tracing::info!("  Message bytes for deferred processing: {:?}", commit_result.message_bytes.is_some());
    
    // Check if we got message_bytes for deferred processing
    if let Some(message_bytes) = &commit_result.message_bytes {
        tracing::info!("✅ Got message bytes for deferred processing ({} bytes)", message_bytes.len());
        
        // === Step 8: Bob manually processes the commit ===
        tracing::info!("Step 8: Bob manually processes the deferred commit");
        
        // Get Bob's current group state
        let bob_groups = bob_nostr_mls.get_groups()?;
        let bob_group = bob_groups.first().unwrap();
        let bob_mls_group_id = GroupId::from_slice(bob_group.mls_group_id.as_slice());
        
        tracing::info!("Bob's group name before processing: {}", bob_group.name);
        
        // Process the commit message for the group using our new function
        let commit_processing_result = bob_nostr_mls.process_commit_message_for_group(
            &bob_mls_group_id,
            message_bytes,
        )?;
        
        tracing::info!("Commit processing result: {:?}", commit_processing_result);
        
        // Let's check what happened to Bob's group after processing
        let bob_groups_after = bob_nostr_mls.get_groups()?;
        let bob_group_after = bob_groups_after.first().unwrap();
        
        tracing::info!("Bob's group after processing:");
        tracing::info!("  MLS Group ID: {:?}", bob_group_after.mls_group_id);
        tracing::info!("  Nostr Group ID: {:?}", bob_group_after.nostr_group_id);
        tracing::info!("  Name: {}", bob_group_after.name);
        tracing::info!("  Description: {}", bob_group_after.description);
        tracing::info!("  Epoch: {}", bob_group_after.epoch);
        
        // Also check if the MLS group state was updated
        let bob_mls_group_after = bob_nostr_mls.load_mls_group(&bob_mls_group_id)?;
        if let Some(mls_group) = bob_mls_group_after {
            tracing::info!("Bob's MLS group after processing:");
            tracing::info!("  Epoch: {}", mls_group.epoch());
            tracing::info!("  Group ID: {:?}", mls_group.group_id());
            
            // Try to extract the extension data
            if let Ok(ext) = crate::extension::NostrGroupDataExtension::from_group(&mls_group) {
                tracing::info!("Bob's MLS group extension data:");
                tracing::info!("  Name: {}", ext.name);
                tracing::info!("  Description: {}", ext.description);
                tracing::info!("  Nostr Group ID: {:?}", ext.nostr_group_id);
            } else {
                tracing::warn!("Failed to extract extension data from Bob's MLS group");
            }
        } else {
            tracing::warn!("Bob's MLS group not found after processing");
        }
        
        // Verify the group name was updated
        let updated_bob_groups = bob_nostr_mls.get_groups()?;
        let updated_bob_group = updated_bob_groups.first().unwrap();
        
        tracing::info!("Group name before: {}", bob_group.name);
        tracing::info!("Group name after: {}", updated_bob_group.name);
        
        if updated_bob_group.name == new_name {
            tracing::info!("✅ SUCCESS: Group name updated via deferred commit processing!");
        } else {
            tracing::warn!("❌ FAILED: Group name not updated. Expected: {}, Got: {}", 
                          new_name, updated_bob_group.name);
            
            // Let's also check Alice's group to see what the expected state should be
            let alice_group = alice_nostr_mls.get_group(&group_id)?.unwrap();
            tracing::info!("Alice's group state (expected):");
            tracing::info!("  Name: {}", alice_group.name);
            tracing::info!("  Description: {}", alice_group.description);
            tracing::info!("  Nostr Group ID: {:?}", alice_group.nostr_group_id);
            tracing::info!("  Epoch: {}", alice_group.epoch);
        }
        
        // Also check Alice's group to see if it was updated
        let alice_group = alice_nostr_mls.get_group(&group_id)?.unwrap();
        tracing::info!("Alice's group name: {}", alice_group.name);
        
    } else {
        tracing::warn!("❌ No message bytes received for deferred processing");
    }
    
    // Also check Alice's group to see if it was updated
    let alice_group = alice_nostr_mls.get_group(&group_id)?.unwrap();
    tracing::info!("Alice's group name: {}", alice_group.name);

    tracing::info!("=== Test completed ===");
    Ok(())
}
