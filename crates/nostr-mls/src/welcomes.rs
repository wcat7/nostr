//! Nostr MLS Welcomes

use nostr::util::hex;
use nostr::{EventId, Timestamp, UnsignedEvent};
use nostr_mls_storage::groups::types as group_types;
use nostr_mls_storage::welcomes::types as welcome_types;
use nostr_mls_storage::NostrMlsStorageProvider;
use openmls::prelude::*;
use tls_codec::Deserialize as TlsDeserialize;

use crate::error::Error;
use crate::extension::NostrGroupDataExtension;
use crate::NostrMls;

/// Welcome preview
#[derive(Debug)]
pub struct WelcomePreview {
    /// Staged welcome
    pub staged_welcome: StagedWelcome,
    /// Nostr data
    pub nostr_group_data: NostrGroupDataExtension,
}

/// Information about a keypackage extracted from a welcome message
#[derive(Debug, Clone)]
pub struct KeyPackageInfo {
    /// Leaf index in the ratchet tree
    pub leaf_index: u32,
    /// Credential identity (usually the Nostr public key)
    pub identity: String,
    /// Signature key (hex encoded)
    pub signature_key: String,
    /// Encryption key (hex encoded)
    pub encryption_key: String,
}

/// Joined group result
#[derive(Debug)]
pub struct JoinedGroupResult {
    /// MLS group
    pub mls_group: MlsGroup,
    /// Nostr data
    pub nostr_group_data: NostrGroupDataExtension,
}

impl<Storage> NostrMls<Storage>
where
    Storage: NostrMlsStorageProvider,
{
    /// Gets a welcome by event id
    pub fn get_welcome(&self, event_id: &EventId) -> Result<Option<welcome_types::Welcome>, Error> {
        let welcome = self
            .storage()
            .find_welcome_by_event_id(event_id)
            .map_err(|e| Error::Welcome(e.to_string()))?;

        Ok(welcome)
    }

    /// Gets pending welcomes
    pub fn get_pending_welcomes(&self) -> Result<Vec<welcome_types::Welcome>, Error> {
        let welcomes = self
            .storage()
            .pending_welcomes()
            .map_err(|e| Error::Welcome(e.to_string()))?;
        Ok(welcomes)
    }

    /// Extracts keypackage information from a welcome message
    ///
    /// This method parses a welcome message and extracts information about the keypackages
    /// that were used to add members to the group. This is useful for analyzing welcome
    /// messages without actually joining the group.
    ///
    /// # Arguments
    ///
    /// * `wrapper_event_id` - The wrapper event ID (kind:1059 event)
    /// * `welcome_event` - The welcome event (kind:444 event)
    ///
    /// # Returns
    ///
    /// A vector of keypackage information extracted from the welcome message
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The welcome message cannot be parsed
    /// - The welcome message is invalid
    /// - The ratchet tree cannot be accessed
    pub fn extract_keypackage_info_from_welcome(
        &self,
        wrapper_event_id: &EventId,
        welcome_event: &UnsignedEvent,
    ) -> Result<Vec<KeyPackageInfo>, Error> {
        let welcome_preview = self.preview_welcome(wrapper_event_id, welcome_event)?;
        let mut keypackage_info = Vec::new();
        
        // Get member information from the staged welcome
        for (leaf_index, member) in welcome_preview.staged_welcome.members().enumerate() {
            // Extract credential identity
            let identity = match BasicCredential::try_from(member.credential.clone()) {
                Ok(basic_cred) => {
                    String::from_utf8(basic_cred.identity().to_vec())
                        .map_err(|e| Error::Utf8(e.utf8_error()))?
                }
                Err(_) => {
                    tracing::warn!("Non-basic credential found in member, skipping");
                    continue;
                }
            };
            
            // Extract signature key
            let signature_key = hex::encode(member.signature_key.as_slice());
            
            // Extract encryption key
            let encryption_key = hex::encode(member.encryption_key.as_slice());
            
            keypackage_info.push(KeyPackageInfo {
                leaf_index: leaf_index as u32,
                identity,
                signature_key,
                encryption_key,
            });
        }
        
        Ok(keypackage_info)
    }



    /// Finds an encoded keypackage from a welcome event
    ///
    /// This method checks if any of your encoded keypackages is included in a welcome message
    /// and returns information about the first one found along with its index.
    ///
    /// # Arguments
    ///
    /// * `encoded_keypackages` - Your encoded keypackages (hex strings) to look for
    /// * `wrapper_event_id` - The wrapper event ID (kind:1059 event)
    /// * `welcome_event` - The welcome event (kind:444 event)
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - `Option<usize>`: The index of the matching keypackage in the input array, if found
    /// - `Option<KeyPackageInfo>`: Information about your keypackage if found in the welcome message
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The welcome message cannot be parsed
    /// - The welcome message is invalid
    /// - Any encoded keypackage cannot be parsed
    pub fn find_encoded_keypackage_from_welcome_event(
        &self,
        encoded_keypackages: &[String],
        wrapper_event_id: &EventId,
        welcome_event: &UnsignedEvent,
    ) -> Result<(Option<usize>, Option<KeyPackageInfo>), Error> {
        let keypackage_info_list = self.extract_keypackage_info_from_welcome(wrapper_event_id, welcome_event)?;
        
        // Check each of your encoded keypackages
        for (index, encoded_keypackage) in encoded_keypackages.iter().enumerate() {
            // Parse the encoded keypackage
            let keypackage = self.parse_serialized_key_package(encoded_keypackage)?;
            let keypackage_signature_key = hex::encode(keypackage.leaf_node().signature_key().as_slice());
            
            // Look for a match
            for info in &keypackage_info_list {
                if info.signature_key == keypackage_signature_key {
                    return Ok((Some(index), Some(info.clone())));
                }
            }
        }
        
        Ok((None, None))
    }

    /// Processes a welcome and stores it in the database
    pub fn process_welcome(
        &self,
        wrapper_event_id: &EventId,
        rumor_event: &UnsignedEvent,
    ) -> Result<welcome_types::Welcome, Error> {
        if self.is_welcome_processed(wrapper_event_id)? {
            let processed_welcome = self
                .storage()
                .find_processed_welcome_by_event_id(wrapper_event_id)
                .map_err(|e| Error::Welcome(e.to_string()))?;
            return match processed_welcome {
                Some(processed_welcome) => {
                    if let Some(welcome_event_id) = processed_welcome.welcome_event_id {
                        self.storage()
                            .find_welcome_by_event_id(&welcome_event_id)
                            .map_err(|e| Error::Welcome(e.to_string()))?
                            .ok_or(Error::MissingWelcomeForProcessedWelcome)
                    } else {
                        Err(Error::MissingWelcomeForProcessedWelcome)
                    }
                }
                None => Err(Error::ProcessedWelcomeNotFound),
            };
        }

        let welcome_preview = self.preview_welcome(wrapper_event_id, rumor_event)?;

        // Create a pending group
        let group = group_types::Group {
            mls_group_id: welcome_preview
                .staged_welcome
                .group_context()
                .group_id()
                .clone(),
            nostr_group_id: welcome_preview.nostr_group_data.nostr_group_id,
            name: welcome_preview.nostr_group_data.name.clone(),
            description: welcome_preview.nostr_group_data.description.clone(),
            admin_pubkeys: welcome_preview.nostr_group_data.admins.clone(),
            last_message_id: None,
            last_message_at: None,
            group_type: if welcome_preview.staged_welcome.members().count() > 2 {
                group_types::GroupType::Group
            } else {
                group_types::GroupType::DirectMessage
            },
            epoch: welcome_preview
                .staged_welcome
                .group_context()
                .epoch()
                .as_u64(),
            state: group_types::GroupState::Pending,
        };

        let mls_group_id: GroupId = group.mls_group_id.clone();

        // Save the pending group
        self.storage()
            .save_group(group)
            .map_err(|e| Error::Group(e.to_string()))?;

        // Save the group relays
        for relay in welcome_preview.nostr_group_data.relays.iter() {
            let group_relay = group_types::GroupRelay {
                mls_group_id: mls_group_id.clone(),
                relay_url: relay.clone(),
            };

            self.storage()
                .save_group_relay(group_relay)
                .map_err(|e| Error::Group(e.to_string()))?;
        }

        let processed_welcome = welcome_types::ProcessedWelcome {
            wrapper_event_id: *wrapper_event_id,
            welcome_event_id: rumor_event.id,
            processed_at: Timestamp::now(),
            state: welcome_types::ProcessedWelcomeState::Processed,
            failure_reason: None,
        };

        let welcome = welcome_types::Welcome {
            id: rumor_event.id.unwrap(),
            event: rumor_event.clone(),
            mls_group_id: welcome_preview
                .staged_welcome
                .group_context()
                .group_id()
                .clone(),
            nostr_group_id: welcome_preview.nostr_group_data.nostr_group_id,
            group_name: welcome_preview.nostr_group_data.name,
            group_description: welcome_preview.nostr_group_data.description,
            group_admin_pubkeys: welcome_preview.nostr_group_data.admins,
            group_relays: welcome_preview.nostr_group_data.relays,
            welcomer: rumor_event.pubkey,
            member_count: welcome_preview.staged_welcome.members().count() as u32,
            state: welcome_types::WelcomeState::Pending,
            wrapper_event_id: *wrapper_event_id,
        };

        self.storage()
            .save_processed_welcome(processed_welcome)
            .map_err(|e| Error::Welcome(e.to_string()))?;

        self.accept_welcome(&welcome)?;

        Ok(welcome)
    }

    /// Accepts a welcome
    pub fn accept_welcome(&self, welcome: &welcome_types::Welcome) -> Result<(), Error> {
        let welcome_preview = self.preview_welcome(&welcome.wrapper_event_id, &welcome.event)?;
        let mls_group = welcome_preview.staged_welcome.into_group(&self.provider)?;

        // Update the welcome to accepted
        let mut welcome = welcome.clone();
        welcome.state = welcome_types::WelcomeState::Accepted;
        self.storage()
            .save_welcome(welcome)
            .map_err(|e| Error::Welcome(e.to_string()))?;

        // Update the group to active
        if let Some(mut group) = self.get_group(mls_group.group_id())? {
            let mls_group_id: GroupId = group.mls_group_id.clone();

            // Update group state
            group.state = group_types::GroupState::Active;

            // Save group
            self.storage().save_group(group).map_err(
                |e: nostr_mls_storage::groups::error::GroupError| Error::Group(e.to_string()),
            )?;

            // Always (re-)save the group relays after saving the group
            for relay_url in welcome_preview.nostr_group_data.relays.into_iter() {
                let group_relay = group_types::GroupRelay {
                    mls_group_id: mls_group_id.clone(),
                    relay_url,
                };

                self.storage()
                    .save_group_relay(group_relay)
                    .map_err(|e| Error::Group(e.to_string()))?;
            }
        }

        Ok(())
    }

    /// Declines a welcome
    pub fn decline_welcome(&self, welcome: &welcome_types::Welcome) -> Result<(), Error> {
        let welcome_preview = self.preview_welcome(&welcome.wrapper_event_id, &welcome.event)?;

        let mls_group_id = welcome_preview.staged_welcome.group_context().group_id();

        // Update the welcome to declined
        let mut welcome = welcome.clone();
        welcome.state = welcome_types::WelcomeState::Declined;
        self.storage()
            .save_welcome(welcome)
            .map_err(|e| Error::Welcome(e.to_string()))?;

        // Update the group to inactive
        if let Some(mut group) = self.get_group(mls_group_id)? {
            group.state = group_types::GroupState::Inactive;
            self.storage()
                .save_group(group)
                .map_err(|e| Error::Group(e.to_string()))?;
        }

        Ok(())
    }

    /// Parses a welcome message and extracts group information.
    ///
    /// This function takes a serialized welcome message and processes it to extract both the staged welcome
    /// and the Nostr-specific group data. This is a lower-level function used by both `preview_welcome_event`
    /// and `join_group_from_welcome`.
    ///
    /// # Arguments
    ///
    /// * `welcome_message` - The serialized welcome message as a byte vector
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - The `StagedWelcome` which can be used to join the group
    /// - The `NostrGroupDataExtension` containing Nostr-specific group metadata
    ///
    /// # Errors
    ///
    /// Returns a `WelcomeError` if:
    /// - The welcome message cannot be deserialized
    /// - The message is not a valid welcome message
    /// - The welcome message cannot be processed
    /// - The group data extension cannot be extracted
    fn parse_serialized_welcome(
        &self,
        mut welcome_message: &[u8],
    ) -> Result<(StagedWelcome, NostrGroupDataExtension), Error> {
        // Parse welcome message
        let welcome_message_in = MlsMessageIn::tls_deserialize(&mut welcome_message)?;

        let welcome: Welcome = match welcome_message_in.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => return Err(Error::InvalidWelcomeMessage),
        };

        let mls_group_config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();

        let staged_welcome =
            StagedWelcome::new_from_welcome(&self.provider, &mls_group_config, welcome, None)?;

        let nostr_group_data =
            NostrGroupDataExtension::from_group_context(staged_welcome.group_context())?;

        Ok((staged_welcome, nostr_group_data))
    }

    /// Previews a welcome message without joining the group.
    ///
    /// This function parses and validates a welcome message, returning information about the group
    /// that can be used to decide whether to join it. Unlike `join_group_from_welcome`, this does
    /// not actually join the group.
    ///
    /// # Arguments
    ///
    /// * `nostr_mls` - The NostrMls instance containing MLS configuration and provider
    /// * `welcome_message` - The serialized welcome message as a byte vector
    ///
    /// # Returns
    ///
    /// A `WelcomePreview` containing the staged welcome and group data on success,
    /// or a `WelcomeError` on failure.
    ///
    /// # Errors
    ///
    /// Returns a `WelcomeError` if:
    /// - The welcome message cannot be parsed
    /// - The welcome message is invalid
    pub fn preview_welcome(
        &self,
        wrapper_event_id: &EventId,
        welcome_event: &UnsignedEvent,
    ) -> Result<WelcomePreview, Error> {
        let hex_content = match hex::decode(&welcome_event.content) {
            Ok(content) => content,
            Err(e) => {
                let error_string = format!("Error hex decoding welcome event: {:?}", e);
                let processed_welcome = welcome_types::ProcessedWelcome {
                    wrapper_event_id: *wrapper_event_id,
                    welcome_event_id: welcome_event.id,
                    processed_at: Timestamp::now(),
                    state: welcome_types::ProcessedWelcomeState::Failed,
                    failure_reason: Some(error_string.clone()),
                };

                self.storage()
                    .save_processed_welcome(processed_welcome)
                    .map_err(|e| Error::Welcome(e.to_string()))?;

                tracing::error!(target: "nostr_mls::welcomes::process_welcome", "Error processing welcome: {}", error_string);

                return Err(Error::Welcome(error_string));
            }
        };

        let welcome_preview = match self.parse_serialized_welcome(&hex_content) {
            Ok((staged_welcome, nostr_group_data)) => WelcomePreview {
                staged_welcome,
                nostr_group_data,
            },
            Err(e) => {
                let error_string = format!("Error previewing welcome: {:?}", e);
                let processed_welcome = welcome_types::ProcessedWelcome {
                    wrapper_event_id: *wrapper_event_id,
                    welcome_event_id: welcome_event.id,
                    processed_at: Timestamp::now(),
                    state: welcome_types::ProcessedWelcomeState::Failed,
                    failure_reason: Some(error_string.clone()),
                };

                self.storage()
                    .save_processed_welcome(processed_welcome)
                    .map_err(|e| Error::Welcome(e.to_string()))?;

                tracing::error!(target: "nostr_mls::welcomes::process_welcome", "Error processing welcome: {}", error_string);

                return Err(Error::Welcome(error_string));
            }
        };

        Ok(welcome_preview)
    }

    /// Check if a welcome has been processed
    fn is_welcome_processed(&self, wrapper_event_id: &EventId) -> Result<bool, Error> {
        let processed_welcome = self
            .storage()
            .find_processed_welcome_by_event_id(wrapper_event_id)
            .map_err(|e| Error::Welcome(e.to_string()))?;
        Ok(processed_welcome.is_some())
    }
}
