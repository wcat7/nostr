// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

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
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    let relay_url = RelayUrl::parse("ws://localhost:8080").unwrap();

    // Generate identities
    let (alice_keys, alice_nostr_mls) = generate_identity();
    println!("Alice pubkey: {}", alice_keys.public_key().to_hex());
    
    let (bob_keys, bob_nostr_mls) = generate_identity();
    println!("Bob pubkey: {}", bob_keys.public_key().to_hex());

    // === Bob creates key package ===
    let (bob_key_package_encoded, tags) =
        bob_nostr_mls.create_key_package_for_event(&bob_keys.public_key(), [relay_url.clone()])?;

    let bob_key_package_event = EventBuilder::new(Kind::MlsKeyPackage, bob_key_package_encoded)
        .tags(tags)
        .build(bob_keys.public_key())
        .sign(&bob_keys)
        .await?;

    // === Alice creates group with Bob ===
    let bob_key_package: KeyPackage = alice_nostr_mls.parse_key_package(&bob_key_package_event)?;

    let group_result = alice_nostr_mls.create_group(
        "Test Group",
        "Testing member removal",
        &alice_keys.public_key(),
        &[bob_keys.public_key()],
        &[bob_key_package],
        vec![alice_keys.public_key()], // Alice is admin
        vec![relay_url.clone()],
    )?;

    let initial_group_id = group_result.group.nostr_group_id;
    let mls_gid = GroupId::from_slice(group_result.group.mls_group_id.as_slice());

    println!("Group created successfully!");
    println!("Initial Group ID: {}", hex::encode(&initial_group_id));

    // === Bob processes welcome message ===
    let welcome_hex = hex::encode(&group_result.serialized_welcome_message);
    let welcome_evt = EventBuilder::new(Kind::MlsWelcome, welcome_hex).build(alice_keys.public_key());
    bob_nostr_mls.process_welcome(&EventId::all_zeros(), &welcome_evt)?;
    println!("Bob joined the group successfully!");

    // === Get pre-secret before removal (this is the key!) ===
    let pre_secret = alice_nostr_mls.exporter_secret(&mls_gid)?;
    println!("Pre-secret obtained before removal");

    // === Alice removes Bob ===
    println!("\n=== Alice removes Bob from the group ===");
    let remove_result = alice_nostr_mls.remove_members(&mls_gid, &[bob_keys.public_key().to_hex()])?;
    println!("Remove commit message created");

    // === Build encrypted commit event using pre_secret and initial group ID ===
    let secret_key = SecretKey::from_slice(&pre_secret.secret).expect("32 bytes secret");
    let tmp_keys = Keys::new(secret_key);
    let encrypted_content = nip44::encrypt(
        tmp_keys.secret_key(),
        &tmp_keys.public_key,
        &remove_result.serialized,
        nip44::Version::default(),
    )?;

    let tag = Tag::custom(TagKind::h(), [hex::encode(initial_group_id)]);
    let remove_event = EventBuilder::new(Kind::MlsGroupMessage, encrypted_content)
        .tag(tag)
        .sign_with_keys(&Keys::generate())?;

    println!("Remove event created: {}", remove_event.id);

    // === Bob processes the remove message ===
    println!("\n=== Bob processes the remove message ===");
    match bob_nostr_mls.process_message(&remove_event) {
        Ok(result) => {
            println!("✅ Message processed successfully!");
            
            if let Some(member_changes) = result.member_changes {
                println!("Member changes detected:");
                println!("  Added members: {:?}", member_changes.added_members);
                println!("  Removed members: {:?}", member_changes.removed_members);
                
                // Check if Bob's pubkey is in the removed_members
                let bob_pubkey_hex = bob_keys.public_key().to_hex();
                if member_changes.removed_members.contains(&bob_pubkey_hex) {
                    println!("🎉 SUCCESS: Bob's pubkey ({}) found in removed_members!", bob_pubkey_hex);
                    println!("✅ Test passed: removed_members correctly contains the removed member's pubkey");
                } else {
                    println!("❌ FAILURE: Bob's pubkey ({}) NOT found in removed_members!", bob_pubkey_hex);
                    println!("   removed_members: {:?}", member_changes.removed_members);
                    println!("   This indicates the issue we're trying to fix.");
                }
            } else {
                println!("❌ FAILURE: No member_changes returned from process_message");
            }
        }
        Err(e) => {
            println!("❌ Error processing message: {:?}", e);
        }
    }

    Ok(())
} 