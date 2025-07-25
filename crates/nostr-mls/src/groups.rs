//! Nostr MLS Group Management
//!
//! This module provides functionality for managing MLS groups in Nostr:
//! - Group creation and configuration
//! - Member management (adding/removing members)
//! - Group state updates and synchronization
//! - Group metadata handling
//! - Group secret management
//!
//! Groups in Nostr MLS have both an MLS group ID and a Nostr group ID. The MLS group ID
//! is used internally by the MLS protocol, while the Nostr group ID is used for
//! relay-based message routing and group discovery.

use std::collections::BTreeSet;
use std::str;

use nostr::{PublicKey, RelayUrl};
use nostr_mls_storage::groups::types as group_types;
use nostr_mls_storage::NostrMlsStorageProvider;
use openmls::extensions::{
    Extension, ExtensionType, LastResortExtension, RequiredCapabilitiesExtension, UnknownExtension,
};
use openmls::group::GroupId;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use tls_codec::Serialize as TlsSerialize;

use super::extension::NostrGroupDataExtension;
use super::NostrMls;
use crate::error::Error;

/// Result of creating a new MLS group
#[derive(Debug)]
pub struct CreateGroupResult {
    /// The stored group
    pub group: group_types::Group,
    /// Serialized welcome message for initial group members
    pub serialized_welcome_message: Vec<u8>,
}

/// Result of updating a member's own leaf node in an MLS group
#[derive(Debug)]
pub struct SelfUpdateResult {
    /// Serialized update message to be sent to the group
    pub serialized_message: Vec<u8>,
    /// The group's exporter secret before the update
    pub current_secret: group_types::GroupExporterSecret,
    /// The group's new exporter secret after the update
    pub new_secret: group_types::GroupExporterSecret,
}

/// Result of batch adding members to a group
#[derive(Debug)]
pub struct AddMembersResult {
    /// Serialized commit message for adding members
    pub commit_message: Vec<u8>,
    /// Serialized welcome message for new members
    pub welcome_message: Vec<u8>,
}

/// Result of committing proposals to a group
#[derive(Debug)]
pub struct CommitProposalResult {
    /// Serialized commit message for the proposal
    pub commit_message: Option<Vec<u8>>,
    /// Optional serialized welcome message if new members are added
    pub welcome_message: Option<Vec<u8>>,
}

/// Wrapper struct for serialized commit/leave messages
#[derive(Debug, Clone)]
pub struct NostrMlsCommitMessage {
    /// Serialized message bytes
    pub serialized: Vec<u8>,
}

impl NostrMlsCommitMessage {
    /// Returns the serialized message as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.serialized
    }
}

impl NostrMlsCommitMessage {
    /// Returns the serialized message as a Vec<u8>.
    pub fn to_vec(self) -> Vec<u8> {
        self.serialized
    }
}

impl<Storage> NostrMls<Storage>
where
    Storage: NostrMlsStorageProvider,
{
    /// Ensures all required extensions are present in the extension list
    /// This helper function maintains consistency across all extension handling
    fn ensure_required_extensions(&self, ext_list: &mut Vec<Extension>) {
        let current_ext_types: std::collections::HashSet<ExtensionType> =
            ext_list.iter().map(|e| e.extension_type()).collect();

        for &required_ext_type in &crate::constant::REQUIRED_EXTENSIONS {
            if !current_ext_types.contains(&required_ext_type) {
                match required_ext_type {
                    ExtensionType::RequiredCapabilities => {
                        // Will be added separately after all other extensions
                        continue;
                    }
                    ExtensionType::LastResort => {
                        // Add LastResort extension if missing
                        ext_list.push(Extension::LastResort(LastResortExtension {}));
                    }
                    ExtensionType::RatchetTree => {
                        // RatchetTree is managed by OpenMLS automatically and may not appear
                        // in the extensions() list even when it's being used internally
                        tracing::debug!("RatchetTree extension not found in extensions list - this is normal as it's managed internally by OpenMLS");
                    }
                    ExtensionType::Unknown(ext_type_id) => {
                        if ext_type_id == crate::constant::NOSTR_GROUP_DATA_EXTENSION_TYPE {
                            // NostrGroupDataExtension should be handled separately
                            continue;
                        }
                        tracing::warn!("Unknown required extension type: {}", ext_type_id);
                    }
                    _ => {
                        tracing::warn!(
                            "Unhandled required extension type: {:?}",
                            required_ext_type
                        );
                    }
                }
            }
        }
    }

    /// Retrieves the leaf node for the current member in an MLS group
    ///
    /// # Arguments
    ///
    /// * `group` - Reference to the MLS group
    ///
    /// # Returns
    ///
    /// * `Ok(&LeafNode)` - The leaf node for the current member
    /// * `Err(Error::OwnLeafNotFound)` - If the member's leaf node is not found
    #[inline]
    pub(crate) fn get_own_leaf<'a>(&self, group: &'a MlsGroup) -> Result<&'a LeafNode, Error> {
        group.own_leaf().ok_or(Error::OwnLeafNotFound)
    }

    /// Loads the signature key pair for the current member in an MLS group
    ///
    /// # Arguments
    ///
    /// * `group` - Reference to the MLS group
    ///
    /// # Returns
    ///
    /// * `Ok(SignatureKeyPair)` - The member's signature key pair
    /// * `Err(Error)` - If the key pair cannot be loaded
    pub(crate) fn load_mls_signer(&self, group: &MlsGroup) -> Result<SignatureKeyPair, Error> {
        let own_leaf: &LeafNode = self.get_own_leaf(group)?;
        let public_key: &[u8] = own_leaf.signature_key().as_slice();

        SignatureKeyPair::read(
            self.provider.storage(),
            public_key,
            group.ciphersuite().signature_algorithm(),
        )
        .ok_or(Error::CantLoadSigner)
    }

    /// Loads an MLS group from storage by its ID
    ///
    /// # Arguments
    ///
    /// * `mls_group_id` - The MLS group ID to load
    ///
    /// # Returns
    ///
    /// * `Ok(Some(MlsGroup))` - The loaded group if found
    /// * `Ok(None)` - If no group exists with the given ID
    /// * `Err(Error)` - If there is an error loading the group
    pub fn load_mls_group(&self, mls_group_id: &GroupId) -> Result<Option<MlsGroup>, Error> {
        MlsGroup::load(self.provider.storage(), mls_group_id)
            .map_err(|e| Error::Provider(e.to_string()))
    }

    /// Exports the current epoch's secret key from an MLS group
    ///
    /// This secret is used for NIP-44 message encryption in Group Message Events (kind:445).
    /// The secret is cached in storage to avoid re-exporting it for each message.
    ///
    /// # Arguments
    ///
    /// * `group_id` - The MLS group ID
    ///
    /// # Returns
    ///
    /// * `Ok(GroupExporterSecret)` - The exported secret
    /// * `Err(Error)` - If the group is not found or there is an error exporting the secret
    pub fn exporter_secret(
        &self,
        group_id: &GroupId,
    ) -> Result<group_types::GroupExporterSecret, Error> {
        let group = self.load_mls_group(group_id)?.ok_or(Error::GroupNotFound)?;

        match self
            .storage()
            .get_group_exporter_secret(group_id, group.epoch().as_u64())
            .map_err(|e| Error::Group(e.to_string()))?
        {
            Some(group_exporter_secret) => Ok(group_exporter_secret),
            // If it's not already in the storage, export the secret and save it
            None => {
                let export_secret: [u8; 32] = group
                    .export_secret(&self.provider, "nostr", b"nostr", 32)?
                    .try_into()
                    .map_err(|_| {
                        Error::Group("Failed to convert export secret to [u8; 32]".to_string())
                    })?;
                let group_exporter_secret = group_types::GroupExporterSecret {
                    mls_group_id: group_id.clone(),
                    epoch: group.epoch().as_u64(),
                    secret: export_secret,
                };

                self.storage()
                    .save_group_exporter_secret(group_exporter_secret.clone())
                    .map_err(|e| Error::Group(e.to_string()))?;

                Ok(group_exporter_secret)
            }
        }
    }

    /// Retrieves a Nostr MLS group by its MLS group ID
    ///
    /// # Arguments
    ///
    /// * `group_id` - The MLS group ID to look up
    ///
    /// # Returns
    ///
    /// * `Ok(Some(Group))` - The group if found
    /// * `Ok(None)` - If no group exists with the given ID
    /// * `Err(Error)` - If there is an error accessing storage
    pub fn get_group(&self, group_id: &GroupId) -> Result<Option<group_types::Group>, Error> {
        self.storage()
            .find_group_by_mls_group_id(group_id)
            .map_err(|e| Error::Group(e.to_string()))
    }

    /// Retrieves all Nostr MLS groups from storage
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<Group>)` - List of all groups
    /// * `Err(Error)` - If there is an error accessing storage
    pub fn get_groups(&self) -> Result<Vec<group_types::Group>, Error> {
        self.storage()
            .all_groups()
            .map_err(|e| Error::Group(e.to_string()))
    }

    /// Gets the public keys of all members in an MLS group
    ///
    /// # Arguments
    ///
    /// * `group_id` - The MLS group ID
    ///
    /// # Returns
    ///
    /// * `Ok(BTreeSet<PublicKey>)` - Set of member public keys
    /// * `Err(Error)` - If the group is not found or there is an error accessing member data
    pub fn get_members(&self, group_id: &GroupId) -> Result<BTreeSet<PublicKey>, Error> {
        let group = self.load_mls_group(group_id)?.ok_or(Error::GroupNotFound)?;

        // Store members in a variable to extend its lifetime
        let mut members = group.members();
        members.try_fold(BTreeSet::new(), |mut acc, m| {
            let credentials: BasicCredential = BasicCredential::try_from(m.credential)?;
            let hex_bytes: &[u8] = credentials.identity();
            let hex_str: &str = str::from_utf8(hex_bytes)?;
            let public_key = PublicKey::from_hex(hex_str)?;
            acc.insert(public_key);
            Ok(acc)
        })
    }

    /// Gets the current user's public key from an MLS group
    ///
    /// # Arguments
    ///
    /// * `group` - Reference to the MLS group
    ///
    /// # Returns
    ///
    /// * `Ok(PublicKey)` - The current user's public key
    /// * `Err(Error)` - If the user's leaf node is not found or there is an error extracting the public key
    pub(crate) fn get_current_user_pubkey(&self, group: &MlsGroup) -> Result<PublicKey, Error> {
        let own_leaf = self.get_own_leaf(group)?;
        let credentials: BasicCredential =
            BasicCredential::try_from(own_leaf.credential().clone())?;
        let hex_bytes: &[u8] = credentials.identity();
        let hex_str: &str = str::from_utf8(hex_bytes)?;
        let public_key = PublicKey::from_hex(hex_str)?;
        Ok(public_key)
    }

    /// Retrieves the set of relay URLs associated with an MLS group
    ///
    /// # Arguments
    ///
    /// * `mls_group_id` - The MLS group ID
    ///
    /// # Returns
    ///
    /// * `Ok(BTreeSet<RelayUrl>)` - Set of relay URLs where group messages are published
    /// * `Err(Error)` - If there is an error accessing storage or the group is not found
    pub fn get_relays(&self, mls_group_id: &GroupId) -> Result<BTreeSet<RelayUrl>, Error> {
        let relays = self
            .storage()
            .group_relays(mls_group_id)
            .map_err(|e| Error::Group(e.to_string()))?;
        Ok(relays.into_iter().map(|r| r.relay_url).collect())
    }

    /// Generate a fresh random 32-byte Nostr group-id, rebuild the Extensions list
    /// (replacing the existing `NostrGroupDataExtension` and refreshing
    /// `RequiredCapabilitiesExtension`) and return `(Extensions, new_gid,
    /// updated_group_data)`.
    fn rotate_group_id_extensions(
        &self,
        group: &openmls::group::MlsGroup,
    ) -> Result<(Extensions, [u8; 32], NostrGroupDataExtension), Error> {
        use nostr::secp256k1::rand::{rngs::OsRng, RngCore};

        // Clone current group data and inject a new random id
        let mut group_data = NostrGroupDataExtension::from_group(group)?;
        let mut new_gid = [0u8; 32];
        OsRng.fill_bytes(&mut new_gid);
        group_data.set_nostr_group_id(new_gid);

        // Serialize back to raw bytes for Unknown extension
        let serialized_group_data = group_data
            .as_raw()
            .tls_serialize_detached()
            .map_err(|e| Error::Group(e.to_string()))?;

        // Start with all REQUIRED_EXTENSIONS to ensure consistency
        let mut ext_list: Vec<Extension> = Vec::new();

        // Add all existing extensions except the old NostrGroupDataExtension
        for ext in group.extensions().iter() {
            match ext.extension_type() {
                ExtensionType::Unknown(id) if id == group_data.extension_type() => {
                    // Skip old NostrGroupDataExtension, we'll add the updated one below
                    continue;
                }
                ExtensionType::RequiredCapabilities => {
                    // Skip RequiredCapabilities, we'll regenerate it at the end
                    continue;
                }
                _ => {
                    ext_list.push(ext.clone());
                }
            }
        }

        // Add the updated NostrGroupDataExtension
        ext_list.push(Extension::Unknown(
            group_data.extension_type(),
            UnknownExtension(serialized_group_data),
        ));

        // Generate RequiredCapabilities with ALL extension types present
        let all_ext_types: Vec<ExtensionType> =
            ext_list.iter().map(|e| e.extension_type()).collect();

        let req_cap_ext = RequiredCapabilitiesExtension::new(&all_ext_types, &[], &[]);
        ext_list.push(Extension::RequiredCapabilities(req_cap_ext));

        let extensions = Extensions::from_vec(ext_list).map_err(|e| Error::Group(e.to_string()))?;

        tracing::debug!(
            "Rotated extensions: {:?}",
            extensions
                .iter()
                .map(|e| e.extension_type())
                .collect::<Vec<_>>()
        );

        Ok((extensions, new_gid, group_data))
    }

    /// Creates a new MLS group with the specified members and settings.
    ///
    /// This function creates a new MLS group with the given name, description, members, and administrators.
    /// It generates the necessary cryptographic credentials, configures the group with Nostr-specific extensions,
    /// and adds the specified members.
    ///
    /// # Arguments
    ///
    /// * `nostr_mls` - The NostrMls instance containing MLS configuration and provider
    /// * `name` - The name of the group
    /// * `description` - A description of the group
    /// * `member_key_packages` - A vector of KeyPackages for the initial group members
    /// * `admin_pubkeys_hex` - A vector of hex-encoded Nostr public keys for group administrators
    /// * `creator_pubkey_hex` - The hex-encoded Nostr public key of the group creator
    /// * `group_relays` - A vector of relay URLs where group messages will be published
    ///
    /// # Returns
    ///
    /// A `CreateGroupResult` containing:
    /// - The created MLS group
    /// - A serialized welcome message for the initial members
    /// - The Nostr-specific group data
    ///
    /// # Errors
    ///
    /// Returns a `Error` if:
    /// - Credential generation fails
    /// - Group creation fails
    /// - Adding members fails
    /// - Message serialization fails
    pub fn create_group<S1, S2>(
        &self,
        name: S1,
        description: S2,
        creator_public_key: &PublicKey,
        member_pubkeys: &[PublicKey],
        member_key_packages: &[KeyPackage],
        admins: Vec<PublicKey>,
        group_relays: Vec<RelayUrl>,
    ) -> Result<CreateGroupResult, Error>
    where
        S1: Into<String>,
        S2: Into<String>,
    {
        // Validate group members
        self.validate_group_members(creator_public_key, member_pubkeys, &admins)?;

        let (credential, signer) = self.generate_credential_with_key(creator_public_key)?;

        tracing::debug!(
            target: "nostr_mls::groups::create_mls_group",
            "Credential and signer created, {:?}",
            credential
        );

        let group_data =
            NostrGroupDataExtension::new(name, description, admins, group_relays.clone());

        tracing::debug!(
            target: "nostr_mls::groups::create_mls_group",
            "Group data created, {:?}",
            group_data
        );

        let serialized_group_data = group_data
            .as_raw()
            .tls_serialize_detached()
            .expect("Failed to serialize group data");

        let extensions = vec![Extension::Unknown(
            group_data.extension_type(),
            UnknownExtension(serialized_group_data),
        )];
        let extensions =
            Extensions::from_vec(extensions).expect("Couldn't convert extensions vec to Object");

        tracing::debug!(
            target: "nostr_mls::groups::create_mls_group",
            "Group config extensions created, {:?}",
            extensions
        );

        // Build the group config
        let capabilities = self.capabilities();
        let group_config = MlsGroupCreateConfig::builder()
            .ciphersuite(self.ciphersuite)
            .use_ratchet_tree_extension(true)
            .capabilities(capabilities)
            .with_group_context_extensions(extensions)?
            .build();

        tracing::debug!(
            target: "nostr_mls::groups::create_mls_group",
            "Group config built, {:?}",
            group_config
        );

        let mut mls_group =
            MlsGroup::new(&self.provider, &signer, &group_config, credential.clone())?;

        // Add members to the group
        let (_, welcome_out, _group_info) =
            mls_group.add_members(&self.provider, &signer, member_key_packages)?;

        // Merge the pending commit adding the memebers
        mls_group.merge_pending_commit(&self.provider)?;

        // Serialize the welcome message and send it to the members
        let serialized_welcome_message = welcome_out.tls_serialize_detached()?;

        let group_type = if mls_group.members().count() > 2 {
            group_types::GroupType::Group
        } else {
            group_types::GroupType::DirectMessage
        };

        // Save the NostrMLS Group
        let group = group_types::Group {
            mls_group_id: mls_group.group_id().clone(),
            nostr_group_id: group_data.clone().nostr_group_id,
            name: group_data.clone().name,
            description: group_data.clone().description,
            admin_pubkeys: group_data.clone().admins,
            last_message_id: None,
            last_message_at: None,
            group_type,
            epoch: mls_group.epoch().as_u64(),
            state: group_types::GroupState::Active,
        };

        self.storage().save_group(group.clone()).map_err(
            |e: nostr_mls_storage::groups::error::GroupError| Error::Group(e.to_string()),
        )?;

        // Always (re-)save the group relays after saving the group
        for relay_url in group_relays.into_iter() {
            let group_relay = group_types::GroupRelay {
                mls_group_id: group.mls_group_id.clone(),
                relay_url,
            };

            self.storage()
                .save_group_relay(group_relay)
                .map_err(|e| Error::Group(e.to_string()))?;
        }

        Ok(CreateGroupResult {
            group,
            serialized_welcome_message,
        })
    }

    /// Updates the current member's leaf node in an MLS group.
    /// Does not currently support updating any group attributes.
    ///
    /// This function performs a self-update operation in the specified MLS group by:
    /// 1. Loading the group from storage
    /// 2. Generating a new signature keypair
    /// 3. Storing the keypair
    /// 4. Creating and applying a self-update proposal
    ///
    /// # Arguments
    ///
    /// * `nostr_mls` - The NostrMls instance containing MLS configuration and provider
    /// * `mls_group_id` - The ID of the MLS group as a byte vector
    ///
    /// # Returns
    ///
    /// A Result containing a tuple of:
    /// - MlsMessageOut: The self-update message to be sent to the group
    /// - Option<MlsMessageOut>: Optional welcome message if new members are added
    /// - Option<GroupInfo>: Optional updated group info
    ///
    /// # Errors
    ///
    /// Returns a Error if:
    /// - The group cannot be loaded from storage
    /// - The specified group is not found
    /// - Failed to generate or store signature keypair
    /// - Failed to perform self-update operation
    pub fn self_update(&self, group_id: &GroupId) -> Result<SelfUpdateResult, Error> {
        // Load group
        let mut group = self.load_mls_group(group_id)?.ok_or(Error::GroupNotFound)?;

        let current_secret: group_types::GroupExporterSecret = self
            .storage()
            .get_group_exporter_secret(group_id, group.epoch().as_u64())
            .map_err(|e| Error::Group(e.to_string()))?
            .ok_or(Error::GroupExporterSecretNotFound)?;

        tracing::debug!(target: "nostr_openmls::groups::self_update", "Current epoch: {:?}", current_secret.epoch);

        // Load current signer
        let current_signer: SignatureKeyPair = self.load_mls_signer(&group)?;

        // Get own leaf
        let own_leaf = self.get_own_leaf(&group)?;

        let new_signature_keypair = SignatureKeyPair::new(self.ciphersuite.signature_algorithm())?;

        new_signature_keypair
            .store(self.provider.storage())
            .map_err(|e| Error::Provider(e.to_string()))?;

        let pubkey = BasicCredential::try_from(own_leaf.credential().clone())?
            .identity()
            .to_vec();

        let new_credential: BasicCredential = BasicCredential::new(pubkey);
        let new_credential_with_key = CredentialWithKey {
            credential: new_credential.into(),
            signature_key: new_signature_keypair.public().into(),
        };

        let leaf_node_params = LeafNodeParameters::builder()
            .with_credential_with_key(new_credential_with_key)
            .with_capabilities(own_leaf.capabilities().clone())
            .with_extensions(own_leaf.extensions().clone())
            .build();

        let commit_message_bundle = group.self_update_with_new_signer(
            &self.provider,
            &current_signer,
            &new_signature_keypair,
            leaf_node_params,
        )?;

        // Merge the commit
        group.merge_pending_commit(&self.provider)?;

        // Export the new epoch's exporter secret
        let new_secret = self.exporter_secret(group_id)?;

        tracing::debug!(target: "nostr_openmls::groups::self_update", "New epoch: {:?}", new_secret.epoch);

        // Serialize the message
        let serialized_message = commit_message_bundle.commit().tls_serialize_detached()?;

        Ok(SelfUpdateResult {
            serialized_message,
            current_secret,
            new_secret,
        })
    }

    /// Validates the members and admins of a group during creation
    ///
    /// # Arguments
    /// * `creator_pubkey` - The public key of the group creator
    /// * `member_pubkeys` - List of public keys for group members
    /// * `admin_pubkeys` - List of public keys for group admins
    ///
    /// # Returns
    /// * `Ok(true)` if validation passes
    /// * `Err(GroupError::InvalidParameters)` if validation fails
    ///
    /// # Validation Rules
    /// - Creator must be an admin but not included in member list
    /// - All admins must also be members (except creator)
    ///
    /// # Errors
    /// Returns `GroupError::InvalidParameters` with descriptive message if:
    /// - Creator is not an admin
    /// - Creator is in member list
    /// - Any admin, other than the creator, is not a member
    fn validate_group_members(
        &self,
        creator_pubkey: &PublicKey,
        member_pubkeys: &[PublicKey],
        admin_pubkeys: &[PublicKey],
    ) -> Result<bool, Error> {
        // Creator must be an admin
        if !admin_pubkeys.contains(creator_pubkey) {
            return Err(Error::Group("Creator must be an admin".to_string()));
        }

        // Creator must not be included as a member
        if member_pubkeys.contains(creator_pubkey) {
            return Err(Error::Group(
                "Creator must not be included as a member".to_string(),
            ));
        }

        // Check that admins are valid pubkeys and are members
        for pubkey in admin_pubkeys.iter() {
            if !member_pubkeys.contains(pubkey) && creator_pubkey != pubkey {
                return Err(Error::Group("Admin must be a member".to_string()));
            }
        }
        Ok(true)
    }

    /// Batch add members
    pub fn add_members(
        &self,
        group_id: &GroupId,
        key_packages: &[KeyPackage],
    ) -> Result<AddMembersResult, Error> {
        // Load group
        let mut group = self.load_mls_group(group_id)?.ok_or(Error::GroupNotFound)?;

        let signer: SignatureKeyPair = self.load_mls_signer(&group)?;

        // Build Extensions with rotated group id
        let (extensions, _new_gid, group_data) = self.rotate_group_id_extensions(&group)?;

        let bundle = group
            .commit_builder()
            .propose_adds(key_packages.iter().cloned())
            .propose_group_context_extensions(extensions)
            .force_self_update(true)
            .load_psks(self.provider.storage())?
            .build(
                self.provider.rand(),
                self.provider.crypto(),
                &signer,
                |_| true,
            )?
            .stage_commit(&self.provider)?;

        let welcome: MlsMessageOut = bundle.to_welcome_msg().ok_or(Error::Group(
            "No secrets to generate commit message.".to_string(),
        ))?;
        let (commit, _welcome_opt, _group_info) = bundle.into_contents();

        group
            .merge_pending_commit(&self.provider)
            .map_err(|e| Error::Group(e.to_string()))?;

        // persist storage group changes with rotated group ID
        if let Some(mut stored) = self.get_group(group_id)? {
            stored.nostr_group_id = group_data.nostr_group_id;
            stored.epoch = group.epoch().as_u64();
            self.storage()
                .save_group(stored)
                .map_err(|e| Error::Group(e.to_string()))?;
        }

        let serialized_commit = commit
            .tls_serialize_detached()
            .map_err(|e| Error::Group(e.to_string()))?;
        let serialized_welcome = welcome
            .tls_serialize_detached()
            .map_err(|e| Error::Group(e.to_string()))?;

        Ok(AddMembersResult {
            commit_message: serialized_commit,
            welcome_message: serialized_welcome,
        })
    }

    /// Batch remove members
    ///
    /// Returns a NostrMlsCommitMessage containing the serialized commit message for removing members.
    pub fn remove_members(
        &self,
        group_id: &GroupId,
        pubkeys_hex: &[String],
    ) -> Result<NostrMlsCommitMessage, Error> {
        // Load group
        let mut group = self.load_mls_group(group_id)?.ok_or(Error::GroupNotFound)?;

        let signer: SignatureKeyPair = self.load_mls_signer(&group)?;

        // Check if current user is an admin
        let current_user_pubkey = self.get_current_user_pubkey(&group)?;
        let stored_group = self.get_group(group_id)?.ok_or(Error::GroupNotFound)?;

        if !stored_group.admin_pubkeys.contains(&current_user_pubkey) {
            return Err(Error::Group(
                "Only group admins can remove members".to_string(),
            ));
        }

        // Convert pubkeys_hex to leaf indices
        let mut leaf_indices = Vec::new();
        let members = group.members();

        for (index, member) in members.enumerate() {
            let credentials: BasicCredential = BasicCredential::try_from(member.credential)?;
            let hex_bytes: &[u8] = credentials.identity();
            let hex_str: &str = str::from_utf8(hex_bytes)?;

            if pubkeys_hex.contains(&hex_str.to_string()) {
                leaf_indices.push(LeafNodeIndex::new(index as u32));
            }
        }

        if leaf_indices.is_empty() {
            return Err(Error::Group(
                "No matching members found to remove".to_string(),
            ));
        }

        // Build Extensions with rotated group id
        let (extensions, _new_gid, group_data) = self.rotate_group_id_extensions(&group)?;

        // Build commit via builder (single commit with removals & extensions)
        let builder = group
            .commit_builder()
            .propose_removals(leaf_indices.clone())
            .propose_group_context_extensions(extensions);

        let builder = builder
            .load_psks(self.provider.storage())
            .map_err(|e| Error::Group(e.to_string()))?;

        let (commit_out, _welcome_opt, _group_info) = builder
            .build(
                self.provider.rand(),
                self.provider.crypto(),
                &signer,
                |_| true,
            )
            .map_err(|e| Error::Group(e.to_string()))?
            .stage_commit(&self.provider)
            .map_err(|e| Error::Group(e.to_string()))?
            .into_contents();

        group
            .merge_pending_commit(&self.provider)
            .map_err(|e| Error::Group(e.to_string()))?;

        // persist storage update
        if let Some(mut stored) = self.get_group(group_id)? {
            stored.nostr_group_id = group_data.nostr_group_id;
            stored.epoch = group.epoch().as_u64();
            self.storage()
                .save_group(stored)
                .map_err(|e| Error::Group(e.to_string()))?;
        }

        let serialized_commit = commit_out
            .tls_serialize_detached()
            .map_err(|e| Error::Group(e.to_string()))?;

        Ok(NostrMlsCommitMessage {
            serialized: serialized_commit,
        })
    }

    /// Commit proposal
    pub fn commit_proposal(
        &self,
        group_id: &GroupId,
        proposal: QueuedProposal,
    ) -> Result<CommitProposalResult, Error> {
        // Load group
        let mut group = self.load_mls_group(group_id)?.ok_or(Error::GroupNotFound)?;

        // Load signer
        let signer: SignatureKeyPair = self.load_mls_signer(&group)?;

        // Check if current user is an admin
        let current_user_pubkey = self.get_current_user_pubkey(&group)?;
        let stored_group = self.get_group(group_id)?.ok_or(Error::GroupNotFound)?;

        // Store proposal
        group
            .store_pending_proposal(self.provider.storage(), proposal)
            .map_err(|e| Error::Group(e.to_string()))?;

        if !stored_group.admin_pubkeys.contains(&current_user_pubkey) {
            return Ok(CommitProposalResult {
                commit_message: None,
                welcome_message: None,
            });
        }

        // Build Extensions with rotated group id
        let (extensions, _new_gid, group_data) = self.rotate_group_id_extensions(&group)?;

        // Build commit via builder: cover pending proposals + new GroupContextExtensions
        let builder = group
            .commit_builder()
            .propose_group_context_extensions(extensions);

        let builder = builder
            .load_psks(self.provider.storage())
            .map_err(|e| Error::Group(e.to_string()))?;

        let (commit_out, welcome_opt, _group_info) = builder
            .build(
                self.provider.rand(),
                self.provider.crypto(),
                &signer,
                |_| true,
            )
            .map_err(|e| Error::Group(e.to_string()))?
            .stage_commit(&self.provider)
            .map_err(|e| Error::Group(e.to_string()))?
            .into_contents();

        // Merge commit so local state advances
        group
            .merge_pending_commit(&self.provider)
            .map_err(|e| Error::Group(e.to_string()))?;

        // Persist updated group metadata
        if let Some(mut stored) = self.get_group(group_id)? {
            stored.nostr_group_id = group_data.nostr_group_id;
            stored.epoch = group.epoch().as_u64();
            self.storage()
                .save_group(stored)
                .map_err(|e| Error::Group(e.to_string()))?;
        }

        // Serialize outputs
        let commit_bytes = commit_out
            .tls_serialize_detached()
            .map_err(|e| Error::Group(e.to_string()))?;

        let welcome_bytes = match welcome_opt {
            Some(w) => Some(
                w.tls_serialize_detached()
                    .map_err(|e| Error::Group(e.to_string()))?,
            ),
            None => None,
        };

        Ok(CommitProposalResult {
            commit_message: Some(commit_bytes),
            welcome_message: welcome_bytes,
        })
    }

    /// Leave the group
    ///
    /// Returns a NostrMlsCommitMessage containing the serialized leave message.
    pub fn leave_group(&self, group_id: &GroupId) -> Result<NostrMlsCommitMessage, Error> {
        // Load group
        let mut group = self.load_mls_group(group_id)?.ok_or(Error::GroupNotFound)?;

        let signer: SignatureKeyPair = self.load_mls_signer(&group)?;

        let leave_message = group
            .leave_group(&self.provider, &signer)
            .map_err(|e| Error::Group(e.to_string()))?;

        let serialized_leave = leave_message
            .tls_serialize_detached()
            .map_err(|e| Error::Group(e.to_string()))?;

        Ok(NostrMlsCommitMessage {
            serialized: serialized_leave,
        })
    }

    /// Updates the `NostrGroupDataExtension` for an existing MLS group.
    ///
    /// This method allows group administrators to update the public metadata of the
    /// group (name, description, admin list and relay list). The update is
    /// performed through the MLS `update_group_context_extensions` API and
    /// therefore results in a new epoch and a commit that MUST be sent to the
    /// rest of the group.
    ///
    /// On success, it returns a `NostrMlsCommitMessage` containing the serialized
    /// commit message that should be broadcast to the group.
    ///
    /// # Arguments
    /// * `group_id`        - The MLS group id of the group to be updated.
    /// * `name`            - New group name. Pass `None` to keep the current one.
    /// * `description`     - New group description. Pass `None` to keep the current one.
    /// * `admin_pubkeys`   - Complete set of admin public keys. Pass `None` to keep the current set.
    /// * `group_relays`    - Complete set of relay URLs. Pass `None` to keep the current set.
    ///
    /// # Errors
    /// * `Error::GroupNotFound`            - If the MLS group is not found in storage.
    /// * `Error::Group`                    - If the caller is not an admin or an MLS error occurs.
    /// * Other errors bubbled up from storage / serialization routines.
    pub fn update_group_data(
        &self,
        group_id: &GroupId,
        name: Option<String>,
        description: Option<String>,
        admin_pubkeys: Option<Vec<PublicKey>>,
        group_relays: Option<Vec<RelayUrl>>,
    ) -> Result<NostrMlsCommitMessage, Error> {
        // 1. Load the MLS group from storage.
        let mut mls_group = self.load_mls_group(group_id)?.ok_or(Error::GroupNotFound)?;

        // 2. Extract the current group data extension so we can modify it.
        let mut group_data = NostrGroupDataExtension::from_group(&mls_group)?;

        // 3. Ensure that the current user is an admin of the group.
        let current_user_pk = self.get_current_user_pubkey(&mls_group)?;
        if !group_data.admins.contains(&current_user_pk) {
            return Err(Error::Group(
                "Only group admins can update group data".to_string(),
            ));
        }

        // 4. Apply updates if provided.
        if let Some(new_name) = name {
            group_data.set_name(new_name);
        }
        if let Some(new_description) = description {
            group_data.set_description(new_description);
        }
        if let Some(new_admins) = admin_pubkeys {
            group_data.admins = new_admins.into_iter().collect();
        }
        if let Some(new_relays) = group_relays {
            group_data.relays = new_relays.into_iter().collect();
        }

        // Always rotate the Nostr Group ID to a fresh random value for each metadata update
        {
            use nostr::secp256k1::rand::{rngs::OsRng, RngCore};
            let mut new_group_id = [0u8; 32];
            OsRng.fill_bytes(&mut new_group_id);
            group_data.set_nostr_group_id(new_group_id);
        }

        // 5. Build a new `Extensions` object for the commit. We start with the
        //    current extensions, replace the NostrGroupDataExtension entry, and
        //    keep everything else unchanged so that we don't accidentally drop
        //    required extensions like `RatchetTree`.

        let serialized_group_data = group_data
            .as_raw()
            .tls_serialize_detached()
            .map_err(|e| Error::Group(e.to_string()))?;

        let mut updated_ext_list: Vec<Extension> = mls_group
            .extensions()
            .iter()
            .filter(|ext| {
                // Filter out the old NostrGroupDataExtension and RequiredCapabilities
                match ext.extension_type() {
                    ExtensionType::Unknown(id) if id == group_data.extension_type() => false,
                    ExtensionType::RequiredCapabilities => false,
                    _ => true,
                }
            })
            .cloned()
            .collect();

        // Insert the updated NostrGroupDataExtension as Unknown extension
        updated_ext_list.push(Extension::Unknown(
            group_data.extension_type(),
            UnknownExtension(serialized_group_data),
        ));

        // Ensure all REQUIRED_EXTENSIONS are present
        self.ensure_required_extensions(&mut updated_ext_list);

        // Generate RequiredCapabilities with ALL extension types (including required ones)
        let required_ext_types: Vec<ExtensionType> = updated_ext_list
            .iter()
            .map(|e| e.extension_type())
            .collect();

        let req_cap_ext = RequiredCapabilitiesExtension::new(&required_ext_types, &[], &[]);
        updated_ext_list.push(Extension::RequiredCapabilities(req_cap_ext));

        let extensions = Extensions::from_vec(updated_ext_list.clone())
            .map_err(|e| Error::Group(e.to_string()))?;

        // 6. Load signer for committing.
        let signer = self.load_mls_signer(&mls_group)?;

        // 7. Build & stage commit with updated extensions.
        let (commit_out, _welcome_opt, _group_info) = mls_group
            .update_group_context_extensions(&self.provider, extensions, &signer)
            .map_err(|e| Error::Group(e.to_string()))?;

        // 8. Merge the commit so that the local state is up to date.
        mls_group
            .merge_pending_commit(&self.provider)
            .map_err(|e| Error::Group(e.to_string()))?;

        // 9. Persist the updated group metadata in our storage layer.
        if let Some(mut stored_group) = self.get_group(group_id)? {
            stored_group.name = group_data.name.clone();
            stored_group.description = group_data.description.clone();
            stored_group.admin_pubkeys = group_data.admins.clone();
            stored_group.epoch = mls_group.epoch().as_u64();
            stored_group.nostr_group_id = group_data.nostr_group_id;

            self.storage()
                .save_group(stored_group.clone())
                .map_err(|e| Error::Group(e.to_string()))?;

            // (Re-)save relays so that any new ones are persisted.
            for relay_url in group_data.relays.into_iter() {
                let group_relay = group_types::GroupRelay {
                    mls_group_id: stored_group.mls_group_id.clone(),
                    relay_url,
                };

                self.storage()
                    .save_group_relay(group_relay)
                    .map_err(|e| Error::Group(e.to_string()))?;
            }
        }

        // 10. Serialize the commit to bytes so that the caller can broadcast it.
        let serialized_commit = commit_out
            .tls_serialize_detached()
            .map_err(|e| Error::Group(e.to_string()))?;

        Ok(NostrMlsCommitMessage {
            serialized: serialized_commit,
        })
    }
}

#[cfg(test)]
mod tests {
    use nostr::{Keys, PublicKey};

    use crate::tests::create_test_nostr_mls;

    fn create_test_group_members() -> (PublicKey, Vec<PublicKey>, Vec<PublicKey>) {
        let creator = Keys::generate();
        let member1 = Keys::generate();
        let member2 = Keys::generate();

        let creator_pk = creator.public_key();
        let members = vec![member1.public_key(), member2.public_key()];
        let admins = vec![creator_pk, member1.public_key()];

        (creator_pk, members, admins)
    }

    #[test]
    fn test_validate_group_members() {
        let nostr_mls = create_test_nostr_mls();
        let (creator_pk, members, admins) = create_test_group_members();

        // Test valid configuration
        assert!(nostr_mls
            .validate_group_members(&creator_pk, &members, &admins)
            .is_ok());

        // Test creator not in admin list
        let bad_admins = vec![members[0]];
        assert!(nostr_mls
            .validate_group_members(&creator_pk, &members, &bad_admins)
            .is_err());

        // Test creator in member list
        let bad_members = vec![creator_pk, members[0]];
        assert!(nostr_mls
            .validate_group_members(&creator_pk, &bad_members, &admins)
            .is_err());

        // Test admin not in member list
        let non_member = Keys::generate().public_key();
        let bad_admins = vec![creator_pk, non_member];
        assert!(nostr_mls
            .validate_group_members(&creator_pk, &members, &bad_admins)
            .is_err());
    }
}
