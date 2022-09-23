// Bitcoin Dev Kit
// Written in 2020 by Alekos Filini <alekos.filini@gmail.com>
//
// Copyright (c) 2020-2021 Bitcoin Dev Kit Developers
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Database types
//!
//! This module provides the implementation of some defaults database types, along with traits that
//! can be implemented externally to let [`Wallet`]s use customized databases.
//!
//! It's important to note that the databases defined here only contains "blockchain-related" data.
//! They can be seen more as a cache than a critical piece of storage that contains secrets and
//! keys.
//!
//! The currently recommended database is [`sled`], which is a pretty simple key-value embedded
//! database written in Rust. If the `key-value-db` feature is enabled (which by default is),
//! this library automatically implements all the required traits for [`sled::Tree`].
//!
//! [`Wallet`]: crate::wallet::Wallet

use serde::{Deserialize, Serialize};

use bitcoin::hash_types::Txid;
use bitcoin::{OutPoint, Script, Transaction, TxOut};

use crate::error::Error;
use crate::types::*;

pub mod any;
pub use any::{AnyDatabase, AnyDatabaseConfig};

#[cfg(feature = "key-value-db")]
pub(crate) mod keyvalue;

#[cfg(feature = "sqlite")]
pub(crate) mod sqlite;
#[cfg(feature = "sqlite")]
pub use sqlite::SqliteDatabase;

pub mod memory;
pub use memory::MemoryDatabase;

/// Blockchain state at the time of syncing
///
/// Contains only the block time and height at the moment
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncTime {
    /// Block timestamp and height at the time of sync
    pub block_time: BlockTime,
}

/// Structure encapsulates criteria used for deleting
/// spent UTXOs
#[derive(Clone, Debug)]
pub struct DelCriteria {
    /// Minimum number of confirmations on UTXOs to make it eligible for deletion
    pub confirmations: Option<u32>,
    /// Max number of allowable spent UTXOs in the database
    pub threshold_size: Option<u64>,
}

/// Trait for operations that can be batched
///
/// This trait defines the list of operations that must be implemented on the [`Database`] type and
/// the [`BatchDatabase::Batch`] type.
pub trait BatchOperations {
    /// Store a script_pubkey along with its keychain and child number.
    fn set_script_pubkey(
        &mut self,
        script: &Script,
        keychain: KeychainKind,
        child: u32,
    ) -> Result<(), Error>;
    /// Store a [`LocalUtxo`]
    fn set_utxo(&mut self, utxo: &LocalUtxo) -> Result<(), Error>;
    /// Store a raw transaction
    fn set_raw_tx(&mut self, transaction: &Transaction) -> Result<(), Error>;
    /// Store the metadata of a transaction
    fn set_tx(&mut self, transaction: &TransactionDetails) -> Result<(), Error>;
    /// Store the last derivation index for a given keychain.
    fn set_last_index(&mut self, keychain: KeychainKind, value: u32) -> Result<(), Error>;
    /// Store the sync time
    fn set_sync_time(&mut self, sync_time: SyncTime) -> Result<(), Error>;

    /// Delete a script_pubkey given the keychain and its child number.
    fn del_script_pubkey_from_path(
        &mut self,
        keychain: KeychainKind,
        child: u32,
    ) -> Result<Option<Script>, Error>;
    /// Delete the data related to a specific script_pubkey, meaning the keychain and the child
    /// number.
    fn del_path_from_script_pubkey(
        &mut self,
        script: &Script,
    ) -> Result<Option<(KeychainKind, u32)>, Error>;
    /// Delete a [`LocalUtxo`] given its [`OutPoint`]
    fn del_utxo(&mut self, outpoint: &OutPoint) -> Result<Option<LocalUtxo>, Error>;
    /// Delete a raw transaction given its [`Txid`]
    fn del_raw_tx(&mut self, txid: &Txid) -> Result<Option<Transaction>, Error>;
    /// Delete the metadata of a transaction and optionally the raw transaction itself
    fn del_tx(
        &mut self,
        txid: &Txid,
        include_raw: bool,
    ) -> Result<Option<TransactionDetails>, Error>;
    /// Delete the last derivation index for a keychain.
    fn del_last_index(&mut self, keychain: KeychainKind) -> Result<Option<u32>, Error>;
    /// Reset the sync time to `None`
    ///
    /// Returns the removed value
    fn del_sync_time(&mut self) -> Result<Option<SyncTime>, Error>;
}

/// Trait for reading data from a database
///
/// This traits defines the operations that can be used to read data out of a database
pub trait Database: BatchOperations {
    /// Read and checks the descriptor checksum for a given keychain.
    ///
    /// Should return [`Error::ChecksumMismatch`](crate::error::Error::ChecksumMismatch) if the
    /// checksum doesn't match. If there's no checksum in the database, simply store it for the
    /// next time.
    fn check_descriptor_checksum<B: AsRef<[u8]>>(
        &mut self,
        keychain: KeychainKind,
        bytes: B,
    ) -> Result<(), Error>;

    /// Return the list of script_pubkeys
    fn iter_script_pubkeys(&self, keychain: Option<KeychainKind>) -> Result<Vec<Script>, Error>;
    /// Return the list of [`LocalUtxo`]s
    fn iter_utxos(&self) -> Result<Vec<LocalUtxo>, Error>;
    /// Return the list of raw transactions
    fn iter_raw_txs(&self) -> Result<Vec<Transaction>, Error>;
    /// Return the list of transactions metadata
    fn iter_txs(&self, include_raw: bool) -> Result<Vec<TransactionDetails>, Error>;

    /// Fetch a script_pubkey given the child number of a keychain.
    fn get_script_pubkey_from_path(
        &self,
        keychain: KeychainKind,
        child: u32,
    ) -> Result<Option<Script>, Error>;
    /// Fetch the keychain and child number of a given script_pubkey
    fn get_path_from_script_pubkey(
        &self,
        script: &Script,
    ) -> Result<Option<(KeychainKind, u32)>, Error>;
    /// Fetch a [`LocalUtxo`] given its [`OutPoint`]
    fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<LocalUtxo>, Error>;
    /// Fetch a raw transaction given its [`Txid`]
    fn get_raw_tx(&self, txid: &Txid) -> Result<Option<Transaction>, Error>;
    /// Fetch the transaction metadata and optionally also the raw transaction
    fn get_tx(&self, txid: &Txid, include_raw: bool) -> Result<Option<TransactionDetails>, Error>;
    /// Return the last derivation index for a keychain.
    fn get_last_index(&self, keychain: KeychainKind) -> Result<Option<u32>, Error>;
    /// Return the sync time, if present
    fn get_sync_time(&self) -> Result<Option<SyncTime>, Error>;

    /// Increment the last derivation index for a keychain and return it
    ///
    /// It should insert and return `0` if not present in the database
    fn increment_last_index(&mut self, keychain: KeychainKind) -> Result<u32, Error>;

    /// Delete a list of spent utxos from database. Delete all spent utxos if  list is `None`.
    fn del_spent_utxos(
        &mut self,
        to_delete: Option<Vec<OutPoint>>,
    ) -> Result<Vec<LocalUtxo>, Error> {
        if let Some(to_delete) = to_delete {
            let deleted_utxos = to_delete
                .iter()
                .filter_map(|out| self.del_utxo(out).transpose())
                .collect::<Result<Vec<_>, _>>()?;
            Ok(deleted_utxos)
        } else {
            let deleted_utxos = self
                .iter_utxos()?
                .iter()
                .filter(|utxo| utxo.is_spent)
                .filter_map(|out| self.del_utxo(&out.outpoint).transpose())
                .collect::<Result<Vec<_>, _>>()?;
            Ok(deleted_utxos)
        }
    }

    /// Delete UTXOs based on the number of confirmations or
    /// threshold size (number of spent utxos in DB) defined in [`DelCriteria`]
    fn del_spent_utxos_by_criteria(
        &mut self,
        criteria: DelCriteria,
        current_block_height: Option<u32>,
    ) -> Result<Vec<LocalUtxo>, Error> {
        let spent_utxos: Vec<LocalUtxo> = self
            .iter_utxos()?
            .into_iter()
            .filter(|utxo| utxo.is_spent)
            .collect();
        let tx_details = spent_utxos
            .iter()
            .filter_map(|utxo| self.get_tx(&utxo.outpoint.txid, false).transpose())
            .collect::<Result<Vec<_>, _>>()?;

        let txs_conf_heights = tx_details
            .iter()
            .filter_map(|details| details.confirmation_time.as_ref().map(|conf| conf.height))
            .collect::<Vec<_>>();
        let utxos_heights: Vec<(&LocalUtxo, &u32)> =
            spent_utxos.iter().zip(txs_conf_heights.iter()).collect();

        let mut to_delete: Vec<&LocalUtxo> = vec![];
        let mut failed_confirmation_criteria: Vec<(&LocalUtxo, &u32)> = vec![];

        // Choose all utxos to delete by confirmation criteria.
        if criteria.confirmations.is_some() {
            if current_block_height.is_none() {
                return Err(Error::Generic(String::from(
                    "You must have a non-None `current_block_height` when using the `confirmations` criteria",
                )));
            }

            // split utxos_heights pair based on confirmation criteria
            let (pass, fail): (Vec<_>, Vec<_>) =
                utxos_heights.iter().partition(|(_utxo, height)| {
                    (current_block_height.unwrap() - **height) >= criteria.confirmations.unwrap()
                });

            // add utxos that passed confirmation criteria test to `to_delete`
            to_delete.extend(
                pass.iter()
                    .map(|(utxo, _height)| *utxo)
                    .collect::<Vec<&LocalUtxo>>(),
            );

            // add utxos that failed the test to `failed_confirmation_criteria`
            failed_confirmation_criteria.extend(fail.iter());
        }

        // apply threshold criteria on spent utxos
        if criteria.threshold_size.is_some() {
            if failed_confirmation_criteria.is_empty() {
                failed_confirmation_criteria.extend(utxos_heights.iter());
            }

            // only select on threshold if there are spent utxos to be deleted
            if spent_utxos.len() - to_delete.len() > 0 {
                let qty_to_delete = spent_utxos.len() as u64
                    - criteria.threshold_size.unwrap()
                    - to_delete.len() as u64;
                // sort utxos according to confirmation time
                failed_confirmation_criteria.sort_by(|a, b| (a.1).cmp(b.1));

                // pick oldest ones to delete.
                to_delete.extend(
                    failed_confirmation_criteria
                        .iter()
                        .take(qty_to_delete as usize)
                        .map(|(utxo, _height)| *utxo),
                );
            }
        }

        // delete all the selected spent utxos
        self.del_spent_utxos(Some(to_delete.iter().map(|utxo| utxo.outpoint).collect()))
    }
}

/// Trait for a database that supports batch operations
///
/// This trait defines the methods to start and apply a batch of operations.
pub trait BatchDatabase: Database {
    /// Container for the operations
    type Batch: BatchOperations;

    /// Create a new batch container
    fn begin_batch(&self) -> Self::Batch;
    /// Consume and apply a batch of operations
    fn commit_batch(&mut self, batch: Self::Batch) -> Result<(), Error>;
}

/// Trait for [`Database`] types that can be created given a configuration
pub trait ConfigurableDatabase: Database + Sized {
    /// Type that contains the configuration
    type Config: std::fmt::Debug;

    /// Create a new instance given a configuration
    fn from_config(config: &Self::Config) -> Result<Self, Error>;
}

pub(crate) trait DatabaseUtils: Database {
    fn is_mine(&self, script: &Script) -> Result<bool, Error> {
        self.get_path_from_script_pubkey(script)
            .map(|o| o.is_some())
    }

    fn get_raw_tx_or<D>(&self, txid: &Txid, default: D) -> Result<Option<Transaction>, Error>
    where
        D: FnOnce() -> Result<Option<Transaction>, Error>,
    {
        self.get_tx(txid, true)?
            .and_then(|t| t.transaction)
            .map_or_else(default, |t| Ok(Some(t)))
    }

    fn get_previous_output(&self, outpoint: &OutPoint) -> Result<Option<TxOut>, Error> {
        self.get_raw_tx(&outpoint.txid)?
            .map(|previous_tx| {
                if outpoint.vout as usize >= previous_tx.output.len() {
                    Err(Error::InvalidOutpoint(*outpoint))
                } else {
                    Ok(previous_tx.output[outpoint.vout as usize].clone())
                }
            })
            .transpose()
    }
}

impl<T: Database> DatabaseUtils for T {}

#[cfg(test)]
pub mod test {
    use std::str::FromStr;

    use bitcoin::consensus::encode::deserialize;
    use bitcoin::consensus::serialize;
    use bitcoin::hashes::hex::*;
    use bitcoin::*;

    use super::*;

    pub fn test_script_pubkey<D: Database>(mut db: D) {
        let script = Script::from(
            Vec::<u8>::from_hex("76a91402306a7c23f3e8010de41e9e591348bb83f11daa88ac").unwrap(),
        );
        let path = 42;
        let keychain = KeychainKind::External;

        db.set_script_pubkey(&script, keychain, path).unwrap();

        assert_eq!(
            db.get_script_pubkey_from_path(keychain, path).unwrap(),
            Some(script.clone())
        );
        assert_eq!(
            db.get_path_from_script_pubkey(&script).unwrap(),
            Some((keychain, path))
        );
    }

    pub fn test_batch_script_pubkey<D: BatchDatabase>(mut db: D) {
        let mut batch = db.begin_batch();

        let script = Script::from(
            Vec::<u8>::from_hex("76a91402306a7c23f3e8010de41e9e591348bb83f11daa88ac").unwrap(),
        );
        let path = 42;
        let keychain = KeychainKind::External;

        batch.set_script_pubkey(&script, keychain, path).unwrap();

        assert_eq!(
            db.get_script_pubkey_from_path(keychain, path).unwrap(),
            None
        );
        assert_eq!(db.get_path_from_script_pubkey(&script).unwrap(), None);

        db.commit_batch(batch).unwrap();

        assert_eq!(
            db.get_script_pubkey_from_path(keychain, path).unwrap(),
            Some(script.clone())
        );
        assert_eq!(
            db.get_path_from_script_pubkey(&script).unwrap(),
            Some((keychain, path))
        );
    }

    pub fn test_iter_script_pubkey<D: Database>(mut db: D) {
        let script = Script::from(
            Vec::<u8>::from_hex("76a91402306a7c23f3e8010de41e9e591348bb83f11daa88ac").unwrap(),
        );
        let path = 42;
        let keychain = KeychainKind::External;

        db.set_script_pubkey(&script, keychain, path).unwrap();

        assert_eq!(db.iter_script_pubkeys(None).unwrap().len(), 1);
    }

    pub fn test_del_script_pubkey<D: Database>(mut db: D) {
        let script = Script::from(
            Vec::<u8>::from_hex("76a91402306a7c23f3e8010de41e9e591348bb83f11daa88ac").unwrap(),
        );
        let path = 42;
        let keychain = KeychainKind::External;

        db.set_script_pubkey(&script, keychain, path).unwrap();
        assert_eq!(db.iter_script_pubkeys(None).unwrap().len(), 1);

        db.del_script_pubkey_from_path(keychain, path).unwrap();
        assert_eq!(db.iter_script_pubkeys(None).unwrap().len(), 0);
    }

    pub fn test_utxo<D: Database>(mut db: D) {
        let outpoint = OutPoint::from_str(
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:0",
        )
        .unwrap();
        let script = Script::from(
            Vec::<u8>::from_hex("76a91402306a7c23f3e8010de41e9e591348bb83f11daa88ac").unwrap(),
        );
        let txout = TxOut {
            value: 133742,
            script_pubkey: script,
        };
        let utxo = LocalUtxo {
            txout,
            outpoint,
            keychain: KeychainKind::External,
            is_spent: true,
        };

        db.set_utxo(&utxo).unwrap();
        db.set_utxo(&utxo).unwrap();
        assert_eq!(db.iter_utxos().unwrap().len(), 1);
        assert_eq!(db.get_utxo(&outpoint).unwrap(), Some(utxo));
    }

    pub fn test_raw_tx<D: Database>(mut db: D) {
        let hex_tx = Vec::<u8>::from_hex("02000000000101f58c18a90d7a76b30c7e47d4e817adfdd79a6a589a615ef36e360f913adce2cd0000000000feffffff0210270000000000001600145c9a1816d38db5cbdd4b067b689dc19eb7d930e2cf70aa2b080000001600140f48b63160043047f4f60f7f8f551f80458f693f024730440220413f42b7bc979945489a38f5221e5527d4b8e3aa63eae2099e01945896ad6c10022024ceec492d685c31d8adb64e935a06933877c5ae0e21f32efe029850914c5bad012102361caae96f0e9f3a453d354bb37a5c3244422fb22819bf0166c0647a38de39f21fca2300").unwrap();
        let mut tx: Transaction = deserialize(&hex_tx).unwrap();

        db.set_raw_tx(&tx).unwrap();

        let txid = tx.txid();

        assert_eq!(db.get_raw_tx(&txid).unwrap(), Some(tx.clone()));

        // mutate transaction's witnesses
        for tx_in in tx.input.iter_mut() {
            tx_in.witness = Witness::new();
        }

        let updated_hex_tx = serialize(&tx);

        // verify that mutation was successful
        assert_ne!(hex_tx, updated_hex_tx);

        db.set_raw_tx(&tx).unwrap();

        let txid = tx.txid();

        assert_eq!(db.get_raw_tx(&txid).unwrap(), Some(tx));
    }

    pub fn test_tx<D: Database>(mut db: D) {
        let hex_tx = Vec::<u8>::from_hex("0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000").unwrap();
        let tx: Transaction = deserialize(&hex_tx).unwrap();
        let txid = tx.txid();
        let mut tx_details = TransactionDetails {
            transaction: Some(tx),
            txid,
            received: 1337,
            sent: 420420,
            fee: Some(140),
            confirmation_time: Some(BlockTime {
                timestamp: 123456,
                height: 1000,
            }),
        };

        db.set_tx(&tx_details).unwrap();

        // get with raw tx too
        assert_eq!(
            db.get_tx(&tx_details.txid, true).unwrap(),
            Some(tx_details.clone())
        );
        // get only raw_tx
        assert_eq!(
            db.get_raw_tx(&tx_details.txid).unwrap(),
            tx_details.transaction
        );

        // now get without raw_tx
        tx_details.transaction = None;
        assert_eq!(
            db.get_tx(&tx_details.txid, false).unwrap(),
            Some(tx_details)
        );
    }

    pub fn test_list_transaction<D: Database>(mut db: D) {
        let hex_tx = Vec::<u8>::from_hex("0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000").unwrap();
        let tx: Transaction = deserialize(&hex_tx).unwrap();
        let txid = tx.txid();
        let mut tx_details = TransactionDetails {
            transaction: Some(tx),
            txid,
            received: 1337,
            sent: 420420,
            fee: Some(140),
            confirmation_time: Some(BlockTime {
                timestamp: 123456,
                height: 1000,
            }),
        };

        db.set_tx(&tx_details).unwrap();

        // get raw tx
        assert_eq!(db.iter_txs(true).unwrap(), vec![tx_details.clone()]);

        // now get without raw tx
        tx_details.transaction = None;

        // get not raw tx
        assert_eq!(db.iter_txs(false).unwrap(), vec![tx_details.clone()]);
    }

    pub fn test_last_index<D: Database>(mut db: D) {
        db.set_last_index(KeychainKind::External, 1337).unwrap();

        assert_eq!(
            db.get_last_index(KeychainKind::External).unwrap(),
            Some(1337)
        );
        assert_eq!(db.get_last_index(KeychainKind::Internal).unwrap(), None);

        let res = db.increment_last_index(KeychainKind::External).unwrap();
        assert_eq!(res, 1338);
        let res = db.increment_last_index(KeychainKind::Internal).unwrap();
        assert_eq!(res, 0);

        assert_eq!(
            db.get_last_index(KeychainKind::External).unwrap(),
            Some(1338)
        );
        assert_eq!(db.get_last_index(KeychainKind::Internal).unwrap(), Some(0));
    }

    pub fn test_sync_time<D: Database>(mut db: D) {
        assert!(db.get_sync_time().unwrap().is_none());

        db.set_sync_time(SyncTime {
            block_time: BlockTime {
                height: 100,
                timestamp: 1000,
            },
        })
        .unwrap();

        let extracted = db.get_sync_time().unwrap();
        assert!(extracted.is_some());
        assert_eq!(extracted.as_ref().unwrap().block_time.height, 100);
        assert_eq!(extracted.as_ref().unwrap().block_time.timestamp, 1000);

        db.del_sync_time().unwrap();
        assert!(db.get_sync_time().unwrap().is_none());
    }

    pub fn test_iter_raw_txs<D: Database>(mut db: D) {
        let txs = db.iter_raw_txs().unwrap();
        assert!(txs.is_empty());

        let hex_tx = Vec::<u8>::from_hex("0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000").unwrap();
        let first_tx: Transaction = deserialize(&hex_tx).unwrap();

        let hex_tx = Vec::<u8>::from_hex("02000000000101f58c18a90d7a76b30c7e47d4e817adfdd79a6a589a615ef36e360f913adce2cd0000000000feffffff0210270000000000001600145c9a1816d38db5cbdd4b067b689dc19eb7d930e2cf70aa2b080000001600140f48b63160043047f4f60f7f8f551f80458f693f024730440220413f42b7bc979945489a38f5221e5527d4b8e3aa63eae2099e01945896ad6c10022024ceec492d685c31d8adb64e935a06933877c5ae0e21f32efe029850914c5bad012102361caae96f0e9f3a453d354bb37a5c3244422fb22819bf0166c0647a38de39f21fca2300").unwrap();
        let second_tx: Transaction = deserialize(&hex_tx).unwrap();

        db.set_raw_tx(&first_tx).unwrap();
        db.set_raw_tx(&second_tx).unwrap();

        let txs = db.iter_raw_txs().unwrap();

        assert!(txs.contains(&first_tx));
        assert!(txs.contains(&second_tx));
        assert_eq!(txs.len(), 2);
    }

    pub fn test_del_path_from_script_pubkey<D: Database>(mut db: D) {
        let keychain = KeychainKind::External;

        let script = Script::from(
            Vec::<u8>::from_hex("76a91402306a7c23f3e8010de41e9e591348bb83f11daa88ac").unwrap(),
        );
        let path = 42;

        let res = db.del_path_from_script_pubkey(&script).unwrap();

        assert!(res.is_none());

        let _res = db.set_script_pubkey(&script, keychain, path);
        let (chain, child) = db.del_path_from_script_pubkey(&script).unwrap().unwrap();

        assert_eq!(chain, keychain);
        assert_eq!(child, path);

        let res = db.get_path_from_script_pubkey(&script).unwrap();
        assert!(res.is_none());
    }

    pub fn test_iter_script_pubkeys<D: Database>(mut db: D) {
        let keychain = KeychainKind::External;
        let scripts = db.iter_script_pubkeys(Some(keychain)).unwrap();
        assert!(scripts.is_empty());

        let first_script = Script::from(
            Vec::<u8>::from_hex("76a91402306a7c23f3e8010de41e9e591348bb83f11daa88ac").unwrap(),
        );
        let path = 42;

        db.set_script_pubkey(&first_script, keychain, path).unwrap();

        let second_script = Script::from(
            Vec::<u8>::from_hex("00145c9a1816d38db5cbdd4b067b689dc19eb7d930e2").unwrap(),
        );
        let path = 57;

        db.set_script_pubkey(&second_script, keychain, path)
            .unwrap();
        let scripts = db.iter_script_pubkeys(Some(keychain)).unwrap();

        assert!(scripts.contains(&first_script));
        assert!(scripts.contains(&second_script));
        assert_eq!(scripts.len(), 2);
    }

    pub fn test_del_utxo<D: Database>(mut db: D) {
        let outpoint = OutPoint::from_str(
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:0",
        )
        .unwrap();
        let script = Script::from(
            Vec::<u8>::from_hex("76a91402306a7c23f3e8010de41e9e591348bb83f11daa88ac").unwrap(),
        );
        let txout = TxOut {
            value: 133742,
            script_pubkey: script,
        };
        let utxo = LocalUtxo {
            txout,
            outpoint,
            keychain: KeychainKind::External,
            is_spent: true,
        };

        let res = db.del_utxo(&outpoint).unwrap();
        assert!(res.is_none());

        db.set_utxo(&utxo).unwrap();

        let res = db.del_utxo(&outpoint).unwrap();

        assert_eq!(res.unwrap(), utxo);

        let res = db.get_utxo(&outpoint).unwrap();
        assert!(res.is_none());
    }

    pub fn test_del_raw_tx<D: Database>(mut db: D) {
        let hex_tx = Vec::<u8>::from_hex("02000000000101f58c18a90d7a76b30c7e47d4e817adfdd79a6a589a615ef36e360f913adce2cd0000000000feffffff0210270000000000001600145c9a1816d38db5cbdd4b067b689dc19eb7d930e2cf70aa2b080000001600140f48b63160043047f4f60f7f8f551f80458f693f024730440220413f42b7bc979945489a38f5221e5527d4b8e3aa63eae2099e01945896ad6c10022024ceec492d685c31d8adb64e935a06933877c5ae0e21f32efe029850914c5bad012102361caae96f0e9f3a453d354bb37a5c3244422fb22819bf0166c0647a38de39f21fca2300").unwrap();
        let tx: Transaction = deserialize(&hex_tx).unwrap();

        let res = db.del_raw_tx(&tx.txid()).unwrap();

        assert!(res.is_none());

        db.set_raw_tx(&tx).unwrap();

        let res = db.del_raw_tx(&tx.txid()).unwrap();

        assert_eq!(res.unwrap(), tx);

        let res = db.get_raw_tx(&tx.txid()).unwrap();
        assert!(res.is_none());
    }

    pub fn test_del_tx<D: Database>(mut db: D) {
        let hex_tx = Vec::<u8>::from_hex("0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000").unwrap();
        let tx: Transaction = deserialize(&hex_tx).unwrap();
        let txid = tx.txid();
        let mut tx_details = TransactionDetails {
            transaction: Some(tx.clone()),
            txid,
            received: 1337,
            sent: 420420,
            fee: Some(140),
            confirmation_time: Some(BlockTime {
                timestamp: 123456,
                height: 1000,
            }),
        };

        let res = db.del_tx(&tx.txid(), true).unwrap();

        assert!(res.is_none());

        db.set_tx(&tx_details).unwrap();

        let res = db.del_tx(&tx.txid(), false).unwrap();
        tx_details.transaction = None;
        assert_eq!(res.unwrap(), tx_details);

        let res = db.get_tx(&tx.txid(), true).unwrap();
        assert!(res.is_none());

        let res = db.get_raw_tx(&tx.txid()).unwrap();
        assert_eq!(res.unwrap(), tx);

        db.set_tx(&tx_details).unwrap();
        let res = db.del_tx(&tx.txid(), true).unwrap();
        tx_details.transaction = Some(tx.clone());
        assert_eq!(res.unwrap(), tx_details);

        let res = db.get_tx(&tx.txid(), true).unwrap();
        assert!(res.is_none());

        let res = db.get_raw_tx(&tx.txid()).unwrap();
        assert!(res.is_none());
    }

    pub fn test_del_last_index<D: Database>(mut db: D) {
        let keychain = KeychainKind::External;

        let _res = db.increment_last_index(keychain);

        let res = db.get_last_index(keychain).unwrap().unwrap();

        assert_eq!(res, 0);

        let _res = db.increment_last_index(keychain);

        let res = db.del_last_index(keychain).unwrap().unwrap();

        assert_eq!(res, 1);

        let res = db.get_last_index(keychain).unwrap();
        assert!(res.is_none());
    }

    pub fn test_check_descriptor_checksum<D: Database>(mut db: D) {
        // insert checksum associated to keychain
        let checksum = "1cead456".as_bytes();
        let keychain = KeychainKind::External;
        let _res = db.check_descriptor_checksum(keychain, checksum);

        // check if `check_descriptor_checksum` throws
        // `Error::ChecksumMismatch` error if the
        // function is passed a checksum that does
        // not match the one initially inserted
        let checksum = "1cead454".as_bytes();
        let keychain = KeychainKind::External;
        let res = db.check_descriptor_checksum(keychain, checksum);

        assert!(res.is_err());
    }

    pub fn test_del_spent_utxos<D: Database>(mut db: D) {
        // Query database for utxos, to prove that it is empty
        assert_eq!(db.iter_utxos().unwrap().len(), 0);

        let (first_utxo, _second_utxo, third_utxo, fourth_utxo) =
            setup_del_spent_utxo_test(&mut db, false);
        // test that insertion was successful
        assert_eq!(db.iter_utxos().unwrap().len(), 4);

        // call del_spent_utxos with None
        let mut res = db.del_spent_utxos(None).unwrap();
        res.sort_by(|a, b| a.txout.value.cmp(&b.txout.value));
        // verify that the one spent utxo has been deleted.
        assert_eq!(
            res,
            vec![first_utxo.clone(), third_utxo.clone(), fourth_utxo.clone()]
        );
        assert_eq!(db.iter_utxos().unwrap().len(), 1);
        // re-insert the deleted utxo into database
        db.set_utxo(&first_utxo).unwrap();
        db.set_utxo(&third_utxo).unwrap();
        db.set_utxo(&fourth_utxo).unwrap();

        // call del_spent_utxos with vector of utxos
        let mut res = db
            .del_spent_utxos(Some(vec![
                first_utxo.outpoint,
                third_utxo.outpoint,
                fourth_utxo.outpoint,
            ]))
            .unwrap();
        res.sort_by(|a, b| a.txout.value.cmp(&b.txout.value));
        assert_eq!(
            res,
            vec![first_utxo.clone(), third_utxo.clone(), fourth_utxo.clone()]
        );
        assert_eq!(db.iter_utxos().unwrap().len(), 1);
    }

    pub fn test_del_spent_utxos_by_criteria<D: Database>(mut db: D) {
        // Query database for utxos, to prove that it is empty
        assert_eq!(db.iter_utxos().unwrap().len(), 0);

        let (first_utxo, _second_utxo, third_utxo, fourth_utxo) =
            setup_del_spent_utxo_test(&mut db, true);

        // throw error when using `confirmations` criteria with None `current_block_height`
        let res = db.del_spent_utxos_by_criteria(
            DelCriteria {
                threshold_size: None,
                confirmations: Some(100),
            },
            None,
        );
        assert!(res.is_err());

        // delete spent utxos with >= 100 confirmations
        let mut res = db
            .del_spent_utxos_by_criteria(
                DelCriteria {
                    threshold_size: None,
                    confirmations: Some(100),
                },
                Some(104),
            )
            .unwrap();

        assert_eq!(res.len(), 2);
        res.sort_by(|a, b| a.txout.value.cmp(&b.txout.value));
        assert_eq!(res, vec![first_utxo.clone(), third_utxo.clone()]);

        db.set_utxo(&first_utxo).unwrap();
        db.set_utxo(&third_utxo).unwrap();

        // test deleting based on `threshold_size`
        let mut res = db
            .del_spent_utxos_by_criteria(
                DelCriteria {
                    threshold_size: Some(1),
                    confirmations: None,
                },
                None,
            )
            .unwrap();

        assert_eq!(res.len(), 2);
        // assert deleting picked the two oldest by number of confirmations
        res.sort_by(|a, b| a.txout.value.cmp(&b.txout.value));
        assert_eq!(res, vec![first_utxo.clone(), third_utxo.clone()]);

        //query database to confirm that only one item is left and it is the oldest
        let res = db.del_spent_utxos(None).unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res.get(0), Some(&fourth_utxo));

        //re-insert utxos
        db.set_utxo(&first_utxo).unwrap();
        db.set_utxo(&third_utxo).unwrap();
        db.set_utxo(&fourth_utxo).unwrap();

        // combining both criterias
        let mut res = db
            .del_spent_utxos_by_criteria(
                DelCriteria {
                    threshold_size: Some(1),
                    confirmations: Some(100),
                },
                Some(101),
            )
            .unwrap();
        res.sort_by(|a, b| a.txout.value.cmp(&b.txout.value));
        assert_eq!(res, vec![first_utxo.clone(), third_utxo.clone()])
    }

    fn setup_del_spent_utxo_test<D: Database>(
        db: &mut D,
        by_criteria: bool,
    ) -> (LocalUtxo, LocalUtxo, LocalUtxo, LocalUtxo) {
        // insert four utxos into database
        let first_outpoint = OutPoint::from_str(
            "c1b4e695098210a31fe02abffe9005cffc051bbe86ff33e173155bcbdc5821e3:0",
        )
        .unwrap();
        let first_script = Script::from(
            Vec::<u8>::from_hex("76a914db4d1141d0048b1ed15839d0b7a4c488cd368b0e88ac").unwrap(),
        );
        let first_txout = TxOut {
            value: 133742,
            script_pubkey: first_script,
        };
        let first_utxo = LocalUtxo {
            txout: first_txout,
            outpoint: first_outpoint,
            keychain: KeychainKind::External,
            is_spent: true,
        };

        db.set_utxo(&first_utxo).unwrap();

        let second_outpoint = OutPoint::from_str(
            "fc9e4f9c334d55c1dc535bd691a1c159b0f7314c54745522257a905e18a56779:1",
        )
        .unwrap();

        let second_script = Script::from(
            Vec::<u8>::from_hex("76a914824d8a679134215d6d21d25bde3cc63f89ec92eb88ac").unwrap(),
        );

        let second_txout = TxOut {
            value: 2257563,
            script_pubkey: second_script,
        };

        let second_utxo = LocalUtxo {
            txout: second_txout,
            outpoint: second_outpoint,
            keychain: KeychainKind::External,
            is_spent: false,
        };

        db.set_utxo(&second_utxo).unwrap();

        let third_outpoint = OutPoint::from_str(
            "26e14e606105b250e64849cc14a484ce58f0f7f7064e662862001661b726427b:1",
        )
        .unwrap();

        let third_script = Script::from(
            Vec::<u8>::from_hex("76a9140d5a9a6f7aae31ebb3b72bbfd05935de5765e0e688ac").unwrap(),
        );

        let third_txout = TxOut {
            value: 1119096,
            script_pubkey: third_script,
        };

        let third_utxo = LocalUtxo {
            txout: third_txout,
            outpoint: third_outpoint,
            keychain: KeychainKind::External,
            is_spent: true,
        };

        db.set_utxo(&third_utxo).unwrap();

        let fourth_outpoint = OutPoint::from_str(
            "d27cff02d45817a11ac01d0d93a2e439f2d643b5d8bc57f4f7f56aa571104e8c:0",
        )
        .unwrap();

        let fourth_script = Script::from(
            Vec::<u8>::from_hex("76a914899490496bfd1228e7ad5b0e156f1fc50a8f6f7688ac").unwrap(),
        );

        let fourth_txout = TxOut {
            value: 36662433,
            script_pubkey: fourth_script,
        };

        let fourth_utxo = LocalUtxo {
            txout: fourth_txout,
            outpoint: fourth_outpoint,
            keychain: KeychainKind::External,
            is_spent: true,
        };

        db.set_utxo(&fourth_utxo).unwrap();

        if by_criteria {
            // insert four transaction details corresponding to
            // the utxos above.
            let hex_tx = Vec::<u8>::from_hex("01000000017967a5185e907a25225574544c31f7b059c1a191d65b53dcc1554d339c4f9efc010000006a47304402206a2eb16b7b92051d0fa38c133e67684ed064effada1d7f925c842da401d4f22702201f196b10e6e4b4a9fff948e5c5d71ec5da53e90529c8dbd122bff2b1d21dc8a90121039b7bcd0824b9a9164f7ba098408e63e5b7e3cf90835cceb19868f54f8961a825ffffffff014baf2100000000001976a914db4d1141d0048b1ed15839d0b7a4c488cd368b0e88ac00000000").unwrap();
            let tx: Transaction = deserialize(&hex_tx).unwrap();

            let first_tx_details = TransactionDetails {
                transaction: Some(tx),
                txid: first_outpoint.txid,
                received: 123409,
                sent: 12089221,
                fee: None,
                confirmation_time: Some(BlockTime {
                    height: 1,
                    timestamp: 2300,
                }),
            };

            let hex_tx = Vec::<u8>::from_hex("0100000001e683631b05f0975ae08faa961f7f04ff78e447d6e9aaf2a3c756129c8d5e416e010000006a473044022052d3ecb87afff52af5505111a3998bc3229cf01c87b4e4845d5035addf22696302205ed49c24e2e358c7d9aaf6fe1070dc5abc44c2f60fe66b4921bf1e31bfb05284012102b7cb69ec5400db2382f37d93b4f44e3ed0ffa8ec67ce19875dd65eb39f9656e2ffffffff0284611a00000000001976a914f884901b74ba2ddf5690b790d8b71026b09b4f3e88ac9b722200000000001976a914824d8a679134215d6d21d25bde3cc63f89ec92eb88ac00000000").unwrap();
            let tx: Transaction = deserialize(&hex_tx).unwrap();

            let second_tx_details = TransactionDetails {
                transaction: Some(tx),
                txid: second_outpoint.txid,
                received: 123409,
                sent: 12089221,
                fee: None,
                confirmation_time: Some(BlockTime {
                    height: 2,
                    timestamp: 2300,
                }),
            };

            let hex_tx = Vec::<u8>::from_hex("0100000001ad0fbcadb0ccc2fa18f10a51edf30493bf1ac34cfdde74c4738750d39b866d10000000006a47304402200ff42a80137dac2436a97a06d7e2cc8bec0c6586c9dfbb5bea3237716849e034022004a44b16c15732bd358ee5a403d7fc45095b060da5fc73a2859329896803f6e201210332e610a6316a8e40e35f253b721480545720103a5eda2f0913d6d30ffc0464e1ffffffff0201e54104000000001976a9143143aa08466c800b6855171863dc6966fd8c4a7888ac78131100000000001976a9140d5a9a6f7aae31ebb3b72bbfd05935de5765e0e688ac00000000").unwrap();
            let tx: Transaction = deserialize(&hex_tx).unwrap();

            let third_tx_details = TransactionDetails {
                transaction: Some(tx),
                txid: third_outpoint.txid,
                received: 123409,
                sent: 12089221,
                fee: None,
                confirmation_time: Some(BlockTime {
                    height: 3,
                    timestamp: 2300,
                }),
            };

            let hex_tx = Vec::<u8>::from_hex("01000000017b4226b76116006228664e06f7f7f058ce84a414cc4948e650b20561604ee126000000006a47304402203a546b99d08183fea83756a11bc656fa887a7920575d058da190d952ef2c03d5022006880e95bb4376be9430c1b85894b5bc22c65738e1564abdf13af62d7162e51f012103e29924d80bb8b828f9af05902e067b4f901f244338954cd48ce9ad224acca4e5ffffffff02a16c2f02000000001976a914899490496bfd1228e7ad5b0e156f1fc50a8f6f7688acb8661202000000001976a9144de7f7fa6aead6469f6439ae271fb31677771afb88ac00000000").unwrap();
            let tx: Transaction = deserialize(&hex_tx).unwrap();

            let fourth_tx_details = TransactionDetails {
                transaction: Some(tx),
                txid: fourth_outpoint.txid,
                received: 123409,
                sent: 12089221,
                fee: None,
                confirmation_time: Some(BlockTime {
                    height: 5,
                    timestamp: 2300,
                }),
            };

            db.set_tx(&first_tx_details).unwrap();
            db.set_tx(&second_tx_details).unwrap();
            db.set_tx(&third_tx_details).unwrap();
            db.set_tx(&fourth_tx_details).unwrap();
        }

        (first_utxo, second_utxo, third_utxo, fourth_utxo)
    }

    // TODO: more tests...
}
