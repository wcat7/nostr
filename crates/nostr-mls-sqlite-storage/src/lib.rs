//! SQLite-based storage implementation for Nostr MLS.
//!
//! This module provides a SQLite-based storage implementation for the Nostr MLS (Messaging Layer Security)
//! crate. It implements the [`NostrMlsStorageProvider`] trait, allowing it to be used within the Nostr MLS context.
//!
//! SQLite-based storage is persistent and will be saved to a file. It's useful for production applications
//! where data persistence is required.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rustdoc::bare_urls)]

use std::path::Path;
use std::sync::{Arc, Mutex};

use nostr_mls_storage::{Backend, NostrMlsStorageProvider};
use openmls_sqlite_storage::{Codec, SqliteStorageProvider};
use rusqlite::Connection;
use serde::de::DeserializeOwned;
use serde::Serialize;

mod db;
pub mod error;
mod groups;
mod messages;
mod migrations;
mod welcomes;

use self::error::Error;

// Define a type alias for the specific SqliteStorageProvider we're using
type MlsStorage = SqliteStorageProvider<JsonCodec, Connection>;

// TODO: make this private?
/// A codec for JSON serialization and deserialization.
#[derive(Default)]
pub struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    #[inline]
    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    #[inline]
    fn from_slice<T>(slice: &[u8]) -> Result<T, Self::Error>
    where
        T: DeserializeOwned,
    {
        serde_json::from_slice(slice)
    }
}

/// A SQLite-based storage implementation for Nostr MLS.
///
/// This struct implements the NostrMlsStorageProvider trait for SQLite databases.
/// It directly interfaces with a SQLite database for storing MLS data.
pub struct NostrMlsSqliteStorage {
    /// The OpenMLS storage implementation
    openmls_storage: MlsStorage,
    /// The SQLite connection
    db_connection: Arc<Mutex<Connection>>,
}

impl NostrMlsSqliteStorage {
    /// Creates a new [`NostrMlsSqliteStorage`] with the provided file path.
    ///
    /// # Arguments
    ///
    /// * `file_path` - Path to the SQLite database file.
    ///
    /// # Returns
    ///
    /// A Result containing a new instance of [`NostrMlsSqliteStorage`] or an error.
    pub fn new<P>(file_path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        Self::new_with_password(file_path, None)
    }

    /// Creates a new encrypted [`NostrMlsSqliteStorage`] with the provided file path and password.
    ///
    /// This method uses SQLCipher to encrypt the database with the provided password.
    /// The password will be used to encrypt/decrypt the database file.
    ///
    /// # Arguments
    ///
    /// * `file_path` - Path to the SQLite database file.
    /// * `password` - Password for database encryption. If None, the database will not be encrypted.
    ///
    /// # Returns
    ///
    /// A Result containing a new instance of [`NostrMlsSqliteStorage`] or an error.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nostr_mls_sqlite_storage::NostrMlsSqliteStorage;
    ///
    /// // Create an encrypted database
    /// let storage = NostrMlsSqliteStorage::new_with_password("encrypted.db", Some("my_secret_password")).unwrap();
    /// ```
    pub fn new_with_password<P>(file_path: P, password: Option<&str>) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        // Ensure parent directory exists
        if let Some(parent) = file_path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Create or open the SQLite database
        let mls_connection: Connection = Connection::open(&file_path)?;

        // Set encryption key if password is provided
        if let Some(pwd) = password {
            mls_connection.execute_batch(&format!("PRAGMA key = '{}';", pwd))?;
        }

        // Enable foreign keys
        mls_connection.execute_batch("PRAGMA foreign_keys = ON;")?;

        // Create OpenMLS storage
        let mut openmls_storage: MlsStorage = SqliteStorageProvider::new(mls_connection);

        // Initialize the OpenMLS storage
        openmls_storage.initialize()?;

        // Create a new connection for the Nostr MLS storage
        let mut nostr_mls_connection = Connection::open(&file_path)?;

        // Set encryption key for the second connection if password is provided
        if let Some(pwd) = password {
            nostr_mls_connection.execute_batch(&format!("PRAGMA key = '{}';", pwd))?;
        }

        // Enable foreign keys
        nostr_mls_connection.execute_batch("PRAGMA foreign_keys = ON;")?;

        // Apply migrations
        migrations::run_migrations(&mut nostr_mls_connection)?;

        Ok(Self {
            openmls_storage,
            db_connection: Arc::new(Mutex::new(nostr_mls_connection)),
        })
    }

    /// Changes the password of an existing encrypted database.
    ///
    /// This method allows you to change the encryption password of an existing database.
    /// The database must already be opened with the current password.
    ///
    /// # Arguments
    ///
    /// * `new_password` - The new password for the database. If None, encryption will be removed.
    ///
    /// # Returns
    ///
    /// A Result indicating success or failure of the password change operation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nostr_mls_sqlite_storage::NostrMlsSqliteStorage;
    ///
    /// // Open database with current password
    /// let mut storage = NostrMlsSqliteStorage::new_with_password("encrypted.db", Some("old_password")).unwrap();
    /// 
    /// // Change to new password
    /// storage.change_password(Some("new_password")).unwrap();
    /// ```
    pub fn change_password(&self, new_password: Option<&str>) -> Result<(), Error> {
        let conn_guard = self.db_connection.lock().map_err(|e| {
            Error::Database(format!("Failed to acquire database lock: {}", e))
        })?;

        match new_password {
            Some(pwd) => {
                // Change to new password
                conn_guard.execute_batch(&format!("PRAGMA rekey = '{}';", pwd))?;
            }
            None => {
                // Remove encryption - this is more complex and requires exporting to a new unencrypted database
                // For now, we'll return an error indicating this operation is not supported
                return Err(Error::Database(
                    "Removing encryption is not currently supported. Use sqlcipher_export() manually.".to_string()
                ));
            }
        }

        Ok(())
    }

    /// Checks if the database is encrypted by attempting to read the schema.
    ///
    /// This method tries to read from the database without a password to determine
    /// if it's encrypted. If the database is encrypted and no password was provided,
    /// this will return an error.
    ///
    /// # Returns
    ///
    /// A Result indicating whether the database appears to be encrypted.
    pub fn is_encrypted(&self) -> Result<bool, Error> {
        let conn_guard = self.db_connection.lock().map_err(|e| {
            Error::Database(format!("Failed to acquire database lock: {}", e))
        })?;

        // Try to read from sqlite_master table
        let prepare_result = conn_guard.prepare("SELECT name FROM sqlite_master LIMIT 1");
        
        match prepare_result {
            Ok(mut stmt) => {
                let query_result = stmt.query_map([], |_| Ok(()));
                match query_result {
                    Ok(_) => Ok(false), // Successfully read, not encrypted or correct password
                    Err(rusqlite::Error::SqliteFailure(err, _)) => {
                        if err.code == rusqlite::ErrorCode::NotADatabase {
                            Ok(true) // Database is encrypted
                        } else {
                            Err(Error::Rusqlite(rusqlite::Error::SqliteFailure(err, None)))
                        }
                    }
                    Err(e) => Err(Error::Rusqlite(e)),
                }
            }
            Err(rusqlite::Error::SqliteFailure(err, _)) => {
                if err.code == rusqlite::ErrorCode::NotADatabase {
                    Ok(true) // Database is encrypted
                } else {
                    Err(Error::Rusqlite(rusqlite::Error::SqliteFailure(err, None)))
                }
            }
            Err(e) => Err(Error::Rusqlite(e)),
        }
    }

    /// Creates a new in-memory [`NostrMlsSqliteStorage`] for testing purposes.
    ///
    /// # Returns
    ///
    /// A Result containing a new in-memory instance of [`NostrMlsSqliteStorage`] or an error.
    #[cfg(test)]
    pub fn new_in_memory() -> Result<Self, Error> {
        // Create an in-memory SQLite database
        let mls_connection = Connection::open_in_memory()?;

        // Enable foreign keys
        mls_connection.execute_batch("PRAGMA foreign_keys = ON;")?;

        // Create OpenMLS storage
        let mut openmls_storage: MlsStorage = SqliteStorageProvider::new(mls_connection);

        // Initialize the OpenMLS storage
        openmls_storage.initialize()?;

        // For in-memory databases, we need to share the connection
        // to keep the database alive, so we will clone the connection
        // and let OpenMLS use a new handle
        let mut nostr_mls_connection: Connection = Connection::open_in_memory()?;

        // Enable foreign keys
        nostr_mls_connection.execute_batch("PRAGMA foreign_keys = ON;")?;

        // Setup the schema in this connection as well
        migrations::run_migrations(&mut nostr_mls_connection)?;

        Ok(Self {
            openmls_storage,
            db_connection: Arc::new(Mutex::new(nostr_mls_connection)),
        })
    }
}

/// Implementation of [`NostrMlsStorageProvider`] for SQLite-based storage.
impl NostrMlsStorageProvider for NostrMlsSqliteStorage {
    type OpenMlsStorageProvider = MlsStorage;

    /// Returns the backend type.
    ///
    /// # Returns
    ///
    /// [`Backend::SQLite`] indicating this is a SQLite-based storage implementation.
    fn backend(&self) -> Backend {
        Backend::SQLite
    }

    /// Get a reference to the openmls storage provider.
    ///
    /// This method provides access to the underlying OpenMLS storage provider.
    /// This is primarily useful for internal operations and testing.
    ///
    /// # Returns
    ///
    /// A reference to the openmls storage implementation.
    fn openmls_storage(&self) -> &Self::OpenMlsStorageProvider {
        &self.openmls_storage
    }

    /// Get a mutable reference to the openmls storage provider.
    ///
    /// This method provides mutable access to the underlying OpenMLS storage provider.
    /// This is primarily useful for internal operations and testing.
    ///
    /// # Returns
    ///
    /// A mutable reference to the openmls storage implementation.
    fn openmls_storage_mut(&mut self) -> &mut Self::OpenMlsStorageProvider {
        &mut self.openmls_storage
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use openmls::group::GroupId;
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn test_new_in_memory() {
        let storage = NostrMlsSqliteStorage::new_in_memory();
        assert!(storage.is_ok());
        let storage = storage.unwrap();
        assert_eq!(storage.backend(), Backend::SQLite);
    }

    #[test]
    fn test_backend_type() {
        let storage = NostrMlsSqliteStorage::new_in_memory().unwrap();
        assert_eq!(storage.backend(), Backend::SQLite);
        assert!(storage.backend().is_persistent());
    }

    #[test]
    fn test_file_based_storage() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test_db.sqlite");

        // Create a new storage
        let storage = NostrMlsSqliteStorage::new(&db_path);
        assert!(storage.is_ok());

        // Verify file exists
        assert!(db_path.exists());

        // Create a second instance that connects to the same file
        let storage2 = NostrMlsSqliteStorage::new(&db_path);
        assert!(storage2.is_ok());

        // Clean up
        drop(storage);
        drop(storage2);
        temp_dir.close().unwrap();
    }

    #[test]
    fn test_openmls_storage_access() {
        let storage = NostrMlsSqliteStorage::new_in_memory().unwrap();

        // Test that we can get a reference to the openmls storage
        let _openmls_storage = storage.openmls_storage();

        // Test mutable accessor
        let mut mutable_storage = NostrMlsSqliteStorage::new_in_memory().unwrap();
        let _mutable_ref = mutable_storage.openmls_storage_mut();
    }

    #[test]
    fn test_database_tables() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("migration_test.sqlite");

        // Create a new SQLite database
        let storage = NostrMlsSqliteStorage::new(&db_path).unwrap();

        // Verify the database has been properly initialized with migrations
        {
            let conn_guard = storage.db_connection.lock().unwrap();

            // Check if the tables exist
            let mut stmt = conn_guard
                .prepare("SELECT name FROM sqlite_master WHERE type='table'")
                .unwrap();
            let table_names: Vec<String> = stmt
                .query_map([], |row| row.get(0))
                .unwrap()
                .map(|r| r.unwrap())
                .collect();

            // Check for essential tables
            assert!(table_names.contains(&"groups".to_string()));
            assert!(table_names.contains(&"messages".to_string()));
            assert!(table_names.contains(&"welcomes".to_string()));
            assert!(table_names.contains(&"processed_messages".to_string()));
            assert!(table_names.contains(&"processed_welcomes".to_string()));
            assert!(table_names.contains(&"group_relays".to_string()));
            assert!(table_names.contains(&"group_exporter_secrets".to_string()));
        } // conn_guard is dropped here when it goes out of scope

        // Drop explicitly to release all resources
        drop(storage);
        temp_dir.close().unwrap();
    }

    #[test]
    fn test_group_exporter_secrets() {
        use nostr_mls_storage::groups::types::{Group, GroupExporterSecret, GroupState, GroupType};
        use nostr_mls_storage::groups::GroupStorage;

        // Create an in-memory SQLite database
        let storage = NostrMlsSqliteStorage::new_in_memory().unwrap();

        // Create a test group
        let mls_group_id = GroupId::from_slice(vec![1, 2, 3, 4].as_slice());
        let group = Group {
            mls_group_id: mls_group_id.clone(),
            nostr_group_id: [0u8; 32],
            name: "Test Group".to_string(),
            description: "A test group for exporter secrets".to_string(),
            admin_pubkeys: BTreeSet::new(),
            last_message_id: None,
            last_message_at: None,
            group_type: GroupType::Group,
            epoch: 0,
            state: GroupState::Active,
        };

        // Save the group
        storage.save_group(group.clone()).unwrap();

        // Create test group exporter secrets for different epochs
        let secret_epoch_0 = GroupExporterSecret {
            mls_group_id: mls_group_id.clone(),
            epoch: 0,
            secret: [0u8; 32],
        };

        let secret_epoch_1 = GroupExporterSecret {
            mls_group_id: mls_group_id.clone(),
            epoch: 1,
            secret: [0u8; 32],
        };

        // Save the exporter secrets
        storage
            .save_group_exporter_secret(secret_epoch_0.clone())
            .unwrap();
        storage
            .save_group_exporter_secret(secret_epoch_1.clone())
            .unwrap();

        // Test retrieving exporter secrets
        let retrieved_secret_0 = storage.get_group_exporter_secret(&mls_group_id, 0).unwrap();
        assert!(retrieved_secret_0.is_some());
        let retrieved_secret_0 = retrieved_secret_0.unwrap();
        assert_eq!(retrieved_secret_0, secret_epoch_0);

        let retrieved_secret_1 = storage.get_group_exporter_secret(&mls_group_id, 1).unwrap();
        assert!(retrieved_secret_1.is_some());
        let retrieved_secret_1 = retrieved_secret_1.unwrap();
        assert_eq!(retrieved_secret_1, secret_epoch_1);

        // Test non-existent epoch
        let non_existent_epoch = storage
            .get_group_exporter_secret(&mls_group_id, 999)
            .unwrap();
        assert!(non_existent_epoch.is_none());

        // Test non-existent group
        let non_existent_group_id = GroupId::from_slice(&[9, 9, 9, 9]);
        let result = storage.get_group_exporter_secret(&non_existent_group_id, 0);
        assert!(result.is_err());

        // Test overwriting an existing secret
        let updated_secret_0 = GroupExporterSecret {
            mls_group_id: mls_group_id.clone(),
            epoch: 0,
            secret: [0u8; 32],
        };
        storage
            .save_group_exporter_secret(updated_secret_0.clone())
            .unwrap();

        let retrieved_updated_secret = storage
            .get_group_exporter_secret(&mls_group_id, 0)
            .unwrap()
            .unwrap();
        assert_eq!(retrieved_updated_secret, updated_secret_0);

        // Test trying to save a secret for a non-existent group
        let invalid_secret = GroupExporterSecret {
            mls_group_id: non_existent_group_id.clone(),
            epoch: 0,
            secret: [0u8; 32],
        };
        let result = storage.save_group_exporter_secret(invalid_secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_database() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("encrypted_test.db");

        // Create an encrypted database
        let password = "test_password_123";
        let storage = NostrMlsSqliteStorage::new_with_password(&db_path, Some(password));
        assert!(storage.is_ok());
        let storage = storage.unwrap();

        // Verify file exists
        assert!(db_path.exists());

        // Test that we can use the storage normally
        assert_eq!(storage.backend(), Backend::SQLite);

        // Drop the storage to close connections
        drop(storage);

        // Try to open the same database with the correct password
        let storage2 = NostrMlsSqliteStorage::new_with_password(&db_path, Some(password));
        assert!(storage2.is_ok());

        // Try to open the same database without password (should fail)
        let storage3 = NostrMlsSqliteStorage::new_with_password(&db_path, None);
        assert!(storage3.is_err());

        // Try to open with wrong password (should fail)
        let storage4 = NostrMlsSqliteStorage::new_with_password(&db_path, Some("wrong_password"));
        assert!(storage4.is_err());

        // Clean up
        drop(storage2);
        temp_dir.close().unwrap();
    }

    #[test]
    fn test_password_change() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("password_change_test.db");

        let original_password = "original_password";
        let new_password = "new_password";

        // Create an encrypted database
        let storage = NostrMlsSqliteStorage::new_with_password(&db_path, Some(original_password)).unwrap();

        // Change the password
        let result = storage.change_password(Some(new_password));
        assert!(result.is_ok());

        // Drop the storage to close connections
        drop(storage);

        // Try to open with the new password
        let storage2 = NostrMlsSqliteStorage::new_with_password(&db_path, Some(new_password));
        assert!(storage2.is_ok());

        // Try to open with the old password (should fail)
        let storage3 = NostrMlsSqliteStorage::new_with_password(&db_path, Some(original_password));
        assert!(storage3.is_err());

        // Clean up
        drop(storage2);
        temp_dir.close().unwrap();
    }

    #[test]
    fn test_remove_encryption_not_supported() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("remove_encryption_test.db");

        let password = "test_password";

        // Create an encrypted database
        let storage = NostrMlsSqliteStorage::new_with_password(&db_path, Some(password)).unwrap();

        // Try to remove encryption (should fail with not supported error)
        let result = storage.change_password(None);
        assert!(result.is_err());
        
        if let Err(Error::Database(msg)) = result {
            assert!(msg.contains("not currently supported"));
        } else {
            panic!("Expected Database error with 'not currently supported' message");
        }

        // Clean up
        drop(storage);
        temp_dir.close().unwrap();
    }

    #[test]
    fn test_unencrypted_database() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("unencrypted_test.db");

        // Create an unencrypted database
        let storage = NostrMlsSqliteStorage::new_with_password(&db_path, None);
        assert!(storage.is_ok());
        let storage = storage.unwrap();

        // Verify file exists
        assert!(db_path.exists());

        // Test that we can use the storage normally
        assert_eq!(storage.backend(), Backend::SQLite);

        // Drop the storage to close connections
        drop(storage);

        // Try to open the same database without password (should work)
        let storage2 = NostrMlsSqliteStorage::new_with_password(&db_path, None);
        assert!(storage2.is_ok());

        // Clean up
        drop(storage2);
        temp_dir.close().unwrap();
    }
}
