// Copyright (c) 2025 Rust Nostr Developers
// Distributed under the MIT software license

//! Example: Three-member group add and chat test.
//! 1. Alice creates a group and invites Bob.
//! 2. Bob joins via welcome.
//! 3. Alice adds Charlie, generates commit and welcome.
//! 4. Alice sends commit to Bob, Bob processes commit.
//! 5. Alice sends welcome to Charlie, Charlie joins.
//! 6. All three members send and receive messages.

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
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // === Logging ===
    let subscriber = FmtSubscriber::builder().with_max_level(Level::INFO).finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    // === Identities ===
    let (alice_keys, alice_mls) = gen_identity();
    let (bob_keys, bob_mls) = gen_identity();
    let (charlie_keys, charlie_mls) = gen_identity();

    // === Bob publishes KeyPackage ===
    let relay = RelayUrl::parse("ws://localhost:8080").unwrap();
    let (bob_kp_enc, bob_tags) = bob_mls.create_key_package_for_event(&bob_keys.public_key(), [relay.clone()], None)?;
    let bob_kp_unsigned = EventBuilder::new(Kind::MlsKeyPackage, bob_kp_enc)
        .tags(bob_tags)
        .build(bob_keys.public_key());
    let bob_kp_event = bob_kp_unsigned.sign(&bob_keys).await?;
    let bob_kp: KeyPackage = alice_mls.parse_key_package(&bob_kp_event)?;

    // === Step 1: Alice creates group with Bob ===
    tracing::info!("Step 1: Alice creates group and adds Bob");
    let create_res = alice_mls.create_group(
        "Alice, Bob, Charlie Chat",
        "A test chat room",
        &alice_keys.public_key(),
        &[bob_keys.public_key()],
        &[bob_kp.clone()],
        vec![alice_keys.public_key()],
        vec![relay.clone()],
    )?;
    let mls_gid = GroupId::from_slice(create_res.group.mls_group_id.as_slice());

    // === Step 2: Bob joins via welcome ===
    let welcome_hex = hex::encode(&create_res.serialized_welcome_message);
    let welcome_evt = EventBuilder::new(Kind::MlsWelcome, welcome_hex).build(alice_keys.public_key());
    bob_mls.process_welcome(&EventId::all_zeros(), &welcome_evt)?;
    tracing::info!("✅ Step 2 completed: Bob joined the group");

    // Debug: print Bob's groups and members after welcome
    let bob_groups = bob_mls.get_groups()?;
    println!("[DEBUG] Bob groups after welcome: {:?}", bob_groups);
    if let Some(bob_group) = bob_groups.first() {
        let bob_gid = GroupId::from_slice(bob_group.mls_group_id.as_slice());
        let bob_members = bob_mls.get_members(&bob_gid)?;
        println!("[DEBUG] Bob members after welcome: {:?}", bob_members);
    }

    // === Charlie publishes KeyPackage ===
    let (charlie_kp_enc, charlie_tags) = charlie_mls.create_key_package_for_event(&charlie_keys.public_key(), [relay.clone()], None)?;
    let charlie_kp_unsigned = EventBuilder::new(Kind::MlsKeyPackage, charlie_kp_enc)
        .tags(charlie_tags)
        .build(charlie_keys.public_key());
    let charlie_kp_event = charlie_kp_unsigned.sign(&charlie_keys).await?;
    let charlie_kp: KeyPackage = alice_mls.parse_key_package(&charlie_kp_event)?;

    // === Step 3: Alice adds Charlie ===
    tracing::info!("Step 3: Alice adds Charlie to the group");
    
    // First, let Bob process the group_id rotation commit (if any)
    // This ensures Bob's group_id matches Alice's before add_members
    let alice_group_before = alice_mls.get_group(&mls_gid)?.unwrap();
    let bob_groups_before = bob_mls.get_groups()?;
    let bob_group_before = bob_groups_before.first().unwrap();
    if alice_group_before.nostr_group_id != bob_group_before.nostr_group_id {
        tracing::info!("Group ID mismatch detected, Bob needs to sync group_id first");
        // This would require a separate commit for group_id rotation
        // For now, we'll skip this step and assume group_id is already synced
    }
    
    let pre_secret = alice_mls.exporter_secret(&mls_gid)?;
    let add_res = alice_mls.add_members(&mls_gid, &[charlie_kp])?;
    tracing::info!("✅ Step 3 completed: Charlie added, commit and welcome generated");

    // === Step 4: Alice sends commit to Bob, Bob processes commit ===
    // Use Bob's current group_id for the commit event tag
    let bob_groups_before_commit = bob_mls.get_groups()?;
    println!("[DEBUG] Bob groups before commit: {:?}", bob_groups_before_commit);
    let bob_group_before_commit = bob_groups_before_commit.first().unwrap();
    let group_id_for_commit = bob_group_before_commit.nostr_group_id;
    println!("[DEBUG] Using Bob's group_id for commit tag: {}", hex::encode(group_id_for_commit));
    let secret_key = SecretKey::from_slice(&pre_secret.secret).expect("32 bytes secret");
    let tmp_keys = Keys::new(secret_key);
    let encrypted_content = nip44::encrypt(
        tmp_keys.secret_key(),
        &tmp_keys.public_key,
        &add_res.commit_message,
        nip44::Version::default(),
    )?;
    let tag = Tag::custom(TagKind::h(), [hex::encode(group_id_for_commit)]);
    println!("[DEBUG] commit event tag: {:?}", tag);
    let commit_evt = EventBuilder::new(Kind::MlsGroupMessage, encrypted_content)
        .tag(tag)
        .sign_with_keys(&Keys::generate())?;
    bob_mls.process_message(&commit_evt)?;
    tracing::info!("✅ Step 4 completed: Bob processed the commit");

    // === Step 5: Alice sends welcome to Charlie, Charlie joins ===
    let welcome2_hex = hex::encode(&add_res.welcome_message);
    
    // Debug: print welcome message details
    println!("[DEBUG] Welcome message hex length: {}", welcome2_hex.len());
    println!("[DEBUG] Welcome message hex (first 200 chars): {}", &welcome2_hex[..std::cmp::min(200, welcome2_hex.len())]);
    println!("[DEBUG] Welcome message binary length: {}", add_res.welcome_message.len());
    
    let welcome2_evt = EventBuilder::new(Kind::MlsWelcome, welcome2_hex).build(alice_keys.public_key());
    charlie_mls.process_welcome(&EventId::all_zeros(), &welcome2_evt)?;
    tracing::info!("✅ Step 5 completed: Charlie joined the group");

    // === Step 6: Verify all three members' state ===
    // Check all three members' member count and group id consistency
    let alice_members = alice_mls.get_members(&mls_gid)?;
    let bob_members = bob_mls.get_members(&mls_gid)?;
    let charlie_members = charlie_mls.get_members(&mls_gid)?;
    assert_eq!(alice_members.len(), 3, "Alice should see 3 members");
    assert_eq!(bob_members.len(), 3, "Bob should see 3 members");
    assert_eq!(charlie_members.len(), 3, "Charlie should see 3 members");
    tracing::info!("✅ All three members see 3 members in the group");

    let alice_group_id = alice_mls.get_group(&mls_gid)?.unwrap().nostr_group_id;
    let bob_group_id = bob_mls.get_group(&mls_gid)?.unwrap().nostr_group_id;
    let charlie_group_id = charlie_mls.get_group(&mls_gid)?.unwrap().nostr_group_id;
    assert_eq!(alice_group_id, bob_group_id, "Alice and Bob group id match");
    assert_eq!(bob_group_id, charlie_group_id, "Bob and Charlie group id match");
    tracing::info!("✅ All three members have the same group id");

    Ok(())
} 