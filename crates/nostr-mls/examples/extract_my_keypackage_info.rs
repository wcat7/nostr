// Copyright (c) 2025 Rust Nostr Developers
// Distributed under the MIT software license

//! Example: Find encoded keypackage from welcome event
//! This example demonstrates the scenario where:
//! 1. Alice creates 3 keypackages
//! 2. Alice sends one keypackage to Bob
//! 3. Bob uses this keypackage to invite Alice to a group
//! 4. Alice receives the welcome message and finds her keypackage

use nostr_mls::prelude::*;
use nostr_mls_memory_storage::NostrMlsMemoryStorage;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;
use hex;

fn gen_identity() -> (Keys, NostrMls<NostrMlsMemoryStorage>) {
    let keys = Keys::generate();
    let mls = NostrMls::new(NostrMlsMemoryStorage::default());
    (keys, mls)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // === Logging ===
    let subscriber = FmtSubscriber::builder().with_max_level(Level::INFO).finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    // === Identities ===
    let (alice_keys, alice_mls) = gen_identity();
    let (bob_keys, bob_mls) = gen_identity();

    let relay = RelayUrl::parse("ws://localhost:8080").unwrap();

    // === Step 1: Alice creates 3 keypackages ===
    tracing::info!("Step 1: Alice creates 3 keypackages");
    
    let (alice_kp1_enc, _alice_kp1_tags) = alice_mls.create_key_package_for_event(&alice_keys.public_key(), [relay.clone()], Some("test-client"))?;
    let (alice_kp2_enc, alice_kp2_tags) = alice_mls.create_key_package_for_event(&alice_keys.public_key(), [relay.clone()], Some("test-client"))?;
    let (alice_kp3_enc, _alice_kp3_tags) = alice_mls.create_key_package_for_event(&alice_keys.public_key(), [relay.clone()], Some("test-client"))?;
    
    tracing::info!("✅ Alice created 3 keypackages");
    tracing::info!("  KeyPackage 1: {}", &alice_kp1_enc[..32.min(alice_kp1_enc.len())]);
    tracing::info!("  KeyPackage 2: {}", &alice_kp2_enc[..32.min(alice_kp2_enc.len())]);
    tracing::info!("  KeyPackage 3: {}", &alice_kp3_enc[..32.min(alice_kp3_enc.len())]);

    // === Step 2: Alice sends one keypackage to Bob ===
    tracing::info!("Step 2: Alice sends keypackage 2 to Bob");
    
    // Alice publishes keypackage 2 for Bob to use
    let alice_kp2_unsigned = EventBuilder::new(Kind::MlsKeyPackage, alice_kp2_enc.clone())
        .tags(alice_kp2_tags)
        .build(alice_keys.public_key());
    let alice_kp2_event = alice_kp2_unsigned.sign(&alice_keys).await?;
    let alice_kp2: KeyPackage = bob_mls.parse_key_package(&alice_kp2_event)?;
    
    tracing::info!("✅ Alice sent keypackage 2 to Bob");

    // === Step 3: Bob uses Alice's keypackage to invite her to a group ===
    tracing::info!("Step 3: Bob creates a group and invites Alice using her keypackage");
    
    // Bob creates a group with Alice
    let create_res = bob_mls.create_group(
        "Bob and Alice Chat",
        "A private chat between Bob and Alice",
        &bob_keys.public_key(),
        &[alice_keys.public_key()],
        &[alice_kp2.clone()],
        vec![bob_keys.public_key()],
        vec![relay.clone()],
    )?;
    
    tracing::info!("✅ Bob created group and sent welcome message to Alice");

    // === Step 4: Alice receives the welcome message ===
    tracing::info!("Step 4: Alice receives the welcome message");
    
    let welcome_hex = hex::encode(&create_res.serialized_welcome_message);
    let welcome_evt = EventBuilder::new(Kind::MlsWelcome, welcome_hex).build(bob_keys.public_key());
    
    tracing::info!("✅ Alice received welcome message");

    // === Step 5: Alice finds her keypackage in the welcome message ===
    tracing::info!("Step 5: Alice searches for her keypackage in the welcome message");
    
    // Alice has all 3 of her keypackages and wants to find which one was used
    let alice_keypackages = vec![alice_kp1_enc.clone(), alice_kp2_enc.clone(), alice_kp3_enc.clone()];
    
    let (found_index, keypackage_info) = alice_mls.find_encoded_keypackage_from_welcome_event(
        &alice_keypackages, 
        &EventId::all_zeros(), 
        &welcome_evt
    )?;
    
    match (found_index, keypackage_info) {
        (Some(index), Some(info)) => {
            tracing::info!("✅ Alice found her keypackage in the welcome message!");
            tracing::info!("  Used KeyPackage Index: {}", index);
            tracing::info!("  Leaf Index: {}", info.leaf_index);
            tracing::info!("  Identity: {}", info.identity);
            tracing::info!("  Signature Key: {}", info.signature_key);
            tracing::info!("  Encryption Key: {}", info.encryption_key);
            
            if index == 1 {
                tracing::info!("✅ Correct! Bob used Alice's keypackage 2 (index 1)");
            } else {
                tracing::warn!("❌ Unexpected! Bob used Alice's keypackage {} (expected 1)", index);
            }
        }
        _ => {
            tracing::warn!("❌ Alice could not find her keypackage in the welcome message");
        }
    }

    // === Extract all keypackage info from welcome message ===
    tracing::info!("Extracting all keypackage info from welcome message...");
    
    let all_keypackage_info = alice_mls.extract_keypackage_info_from_welcome(&EventId::all_zeros(), &welcome_evt)?;
    
    tracing::info!("Found {} keypackages in welcome message:", all_keypackage_info.len());
    for info in &all_keypackage_info {
        tracing::info!("  Leaf Index: {}", info.leaf_index);
        tracing::info!("  Identity: {}", info.identity);
        tracing::info!("  Signature Key: {}", info.signature_key);
        tracing::info!("  Encryption Key: {}", info.encryption_key);
        tracing::info!("  ---");
    }

    // === Process the welcome to join the group ===
    tracing::info!("Processing welcome message to join group...");
    alice_mls.process_welcome(&EventId::all_zeros(), &welcome_evt)?;
    tracing::info!("✅ Alice successfully joined the group!");

    Ok(())
} 