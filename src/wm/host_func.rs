// This file is part of TRINCI.
//
// Copyright (C) 2021 Affidaty Spa.
//
// TRINCI is free software: you can redistribute it and/or modify it under
// the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// TRINCI is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License
// for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with TRINCI. If not, see <https://www.gnu.org/licenses/>.

//! Generic host functions implementations.
use crate::{
    base::schema::SmartContractEvent,
    crypto::{Hash, PublicKey},
    db::DbFork,
    wm::Wm,
    Account, Error, ErrorKind, Result,
};
use ring::digest;

/// Data required to perform contract persistent actions.
pub struct CallContext<'a> {
    /// Wasm machine reference (None if implementation do not support nested calls).
    pub wm: Option<&'a mut dyn Wm>,
    /// Database reference.
    pub db: &'a mut dyn DbFork,
    /// Current account.
    pub owner: &'a str,
    /// Current account data has been updated.
    pub data_updated: bool,
    /// Nested call depth.
    pub depth: u16,
    /// Network identifier (from Tx)
    pub network: &'a str,
    /// Original transaction submitter (from Tx)
    pub origin: &'a str,
    /// Smart contracts events
    pub events: &'a mut Vec<SmartContractEvent>,
}

/// WASM logging facility.
pub fn log(ctx: &CallContext, msg: &str) {
    debug!("{}: {}", ctx.owner, msg);
}

/// Compute Sha256 from given bytes
pub fn sha256(_ctx: &CallContext, data: Vec<u8>) -> Vec<u8> {
    let digest = digest::digest(&digest::SHA256, &data);
    digest.as_ref().to_vec()
}

/// WASM notification facility.
pub fn emit(ctx: &mut CallContext, event_name: &str, event_data: &[u8]) {
    let smart_contract_hash: Hash = match ctx.db.load_account(ctx.owner) {
        Some(account) => match account.contract {
            Some(contract_hash) => contract_hash,
            None => Hash::default(),
        },
        None => Hash::default(),
    };

    ctx.events.push(SmartContractEvent {
        event_tx: Hash::default(),
        emitter_account: ctx.owner.to_string(),
        // TODO: add smart contract hash
        emitter_smart_contract: smart_contract_hash,
        event_name: event_name.to_string(),
        event_data: event_data.to_vec(),
    });
}

/// Load the data struct from the DB
pub fn load_data(ctx: &mut CallContext, key: &str) -> Vec<u8> {
    ctx.db.load_account_data(ctx.owner, key).unwrap_or_default()
}

/// Store the serialized data struct into DB
pub fn store_data(ctx: &mut CallContext, key: &str, data: Vec<u8>) {
    ctx.db.store_account_data(ctx.owner, key, data);
    ctx.data_updated = true;
}

/// Remove a data struct from the DB by key.
pub fn remove_data(ctx: &mut CallContext, key: &str) {
    ctx.db.remove_account_data(ctx.owner, key);
    ctx.data_updated = true;
}

/// Get the account keys that match with the key_pattern provided
/// key must end with a wildcard `*`
pub fn get_keys(ctx: &mut CallContext, pattern: &str) -> Vec<String> {
    ctx.db
        .load_account_keys(ctx.owner)
        .iter()
        .cloned()
        .filter(|s| pattern.is_empty() || s.starts_with(pattern))
        .collect()
}

/// Returns an account asset field for a given `asset_id`
pub fn load_asset(ctx: &CallContext, account_id: &str) -> Vec<u8> {
    match ctx.db.load_account(account_id) {
        Some(account) => account.load_asset(ctx.owner),
        None => vec![],
    }
}

/// Store an asset as assets entry with key `asset_id`
pub fn store_asset(ctx: &mut CallContext, account_id: &str, value: &[u8]) {
    let mut account = ctx
        .db
        .load_account(account_id)
        .unwrap_or_else(|| Account::new(account_id, None));
    account.store_asset(ctx.owner, value);
    ctx.db.store_account(account);
}

/// Digital signature verification.
pub fn verify(_ctx: &CallContext, pk: &PublicKey, data: &[u8], sign: &[u8]) -> i32 {
    pk.verify(data, sign) as i32
}

/// Returns an account hash contract if present for a given `account_id` key
pub fn get_account_contract(ctx: &CallContext, account_id: &str) -> Option<Hash> {
    match ctx.db.load_account(account_id) {
        Some(account) => account.contract,
        None => None,
    }
}

/// Call a method resident in another account and contract.
/// The input and output arguments are subject to the packing format rules of
/// the called smart contract.
pub fn call(ctx: &mut CallContext, owner: &str, method: &str, data: &[u8]) -> Result<Vec<u8>> {
    // >>>>>>>>>>>>>>> FIXME <<<<<<<<<<<<<<<<<<<<<
    // User shall be able to pass the contract
    match ctx.wm {
        Some(ref mut wm) => wm.call(
            ctx.db,
            ctx.depth + 1,
            ctx.network,
            ctx.origin,
            owner,
            ctx.owner,
            None,
            method,
            data,
            ctx.events,
        ),
        None => Err(Error::new_ext(
            ErrorKind::WasmMachineFault,
            "nested calls not implemented",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::HashAlgorithm;
    use crate::{crypto::sign::tests::create_test_keypair, db::*, wm::*};
    use lazy_static::lazy_static;
    use std::collections::HashMap;
    use std::sync::Mutex;

    const ASSET_ACCOUNT: &str = "QmamzDVuZqkUDwHikjHCkgJXhtgkbiVDTvTYb2aq6qfLbY";

    lazy_static! {
        static ref ACCOUNTS: Mutex<HashMap<String, Account>> = Mutex::new(HashMap::new());
    }

    fn account_id(n: u8) -> String {
        let thread_id: u64 = unsafe { std::mem::transmute(std::thread::current().id()) };
        format!("{:016x}{:02x}", thread_id, n)
    }

    fn store_account(id: String, account: Account) {
        ACCOUNTS.lock().unwrap().insert(id, account);
    }

    fn load_account(id: &str) -> Option<Account> {
        ACCOUNTS.lock().unwrap().get(id).cloned()
    }

    fn create_account(i: u8, asset_value: &[u8]) {
        let id = account_id(i);
        let mut account = Account::new(&id, None);
        account.store_asset(ASSET_ACCOUNT, asset_value);
        account.data_hash = Some(Hash::from_data(
            crate::crypto::HashAlgorithm::Sha256,
            &asset_value,
        ));
        store_account(id, account);
    }

    fn create_wm_mock() -> MockWm {
        let mut wm = MockWm::new();
        wm.expect_call().returning(
            |_db,
             _depth,
             _network,
             _origin,
             _owner,
             _caller,
             _app_hash,
             _method,
             _args,
             _events| Ok(vec![]),
        );
        wm
    }

    fn create_fork_mock() -> MockDbFork {
        let mut fork = MockDbFork::new();
        fork.expect_load_account().returning(|id| load_account(id));
        fork.expect_store_account()
            .returning(|acc| store_account(acc.id.clone(), acc));
        fork.expect_store_account_data().returning(|_, _, _| ());
        fork.expect_state_hash().returning(|_| Hash::default());
        fork
    }

    struct TestData {
        wm: MockWm,
        db: MockDbFork,
        owner: String,
        events: Vec<SmartContractEvent>,
    }

    impl TestData {
        pub fn new() -> Self {
            TestData {
                wm: create_wm_mock(),
                db: create_fork_mock(),
                owner: account_id(0),
                events: Vec::new(),
            }
        }

        pub fn as_wm_context(&mut self) -> CallContext {
            CallContext {
                wm: Some(&mut self.wm),
                db: &mut self.db,
                owner: &self.owner,
                data_updated: false,
                depth: 0,
                network: "skynet",
                origin: &self.owner,
                events: &mut self.events,
            }
        }
    }

    fn prepare_env() -> TestData {
        create_account(0, &[9]);
        create_account(1, &[1]);
        TestData::new()
    }

    #[test]
    fn load_asset_test() {
        let mut ctx = prepare_env();
        let mut ctx = ctx.as_wm_context();
        ctx.owner = ASSET_ACCOUNT;
        let target_account = account_id(0);

        let amount = load_asset(&ctx, &target_account);

        assert_eq!(amount, [9]);
    }

    #[test]
    fn store_asset_test() {
        let mut ctx = prepare_env();
        let mut ctx = ctx.as_wm_context();
        ctx.owner = ASSET_ACCOUNT;
        let target_account = account_id(0);

        store_asset(&mut ctx, &target_account, &[42]);

        let account = load_account(&target_account).unwrap();
        let amount = account.load_asset(ASSET_ACCOUNT);
        assert_eq!(amount, [42]);
    }

    #[test]
    fn verify_success() {
        let mut ctx = prepare_env();
        let ctx = ctx.as_wm_context();
        let keypair = create_test_keypair();
        let data = vec![1, 2, 3];
        let sig = keypair.sign(&data).unwrap();

        let res = verify(&ctx, &keypair.public_key(), &data, &sig);

        assert_eq!(res, 1);
    }

    #[test]
    fn get_account_contract_test() {
        let mut ctx = prepare_env();
        let mut ctx = ctx.as_wm_context();
        ctx.owner = ASSET_ACCOUNT;
        let target_account = account_id(0);

        let amount = get_account_contract(&ctx, &target_account);

        assert_eq!(amount, Some(Hash::from_data(HashAlgorithm::Sha256, &[9])));
    }

    #[test]
    fn sha256_success() {
        let mut ctx = prepare_env();
        let ctx = ctx.as_wm_context();
        let hash = sha256(&ctx, vec![0xfa, 0xfb, 0xfc]);
        assert_eq!(
            hash,
            [
                0x31, 0x46, 0x44, 0x50, 0xce, 0xd0, 0xcf, 0x9f, 0x47, 0x4c, 0x43, 0x55, 0x32, 0x80,
                0xf4, 0x16, 0xd3, 0x89, 0x3f, 0x7e, 0x14, 0x4c, 0xce, 0x7d, 0x5b, 0x46, 0x2d, 0xc0,
                0xe5, 0xd6, 0xe4, 0x98
            ]
        );
    }

    #[test]
    fn verify_fail() {
        let mut ctx = prepare_env();
        let ctx = ctx.as_wm_context();
        let keypair = create_test_keypair();
        let data = vec![1, 2, 3];
        let sig = keypair.sign(&data).unwrap();

        let res = verify(&ctx, &keypair.public_key(), &[1, 2], &sig);

        assert_eq!(res, 0);
    }
}
