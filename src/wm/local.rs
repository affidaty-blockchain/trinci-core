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

use super::AppInput;
use crate::{
    base::serialize::{self, rmp_serialize},
    crypto::Hash,
    db::*,
    wm::{
        host_func::{self, CallContext},
        AppOutput, Wm,
    },
    Account, Error, ErrorKind, Result,
};
use serialize::rmp_deserialize;
use std::{
    collections::HashMap,
    slice,
    time::{SystemTime, UNIX_EPOCH},
};
use wasmtime::{
    AsContext, AsContextMut, Caller, Config, Engine, Extern, Func, Instance, Memory, Module, Store,
    StoreContext, StoreContextMut, Trap, TypedFunc,
};

pub type WasmSlice = u64;

/// Combine two i32 into one u64
#[inline]
fn wslice_create(offset: i32, length: i32) -> WasmSlice {
    ((offset as u64) << 32) | (length as u64) & 0x00000000ffffffff
}

/// Split one u64 into two i32
#[inline]
fn wslice_split(wslice: WasmSlice) -> (i32, i32) {
    (
        ((wslice & 0xffffffff00000000) >> 32) as i32,
        (wslice & 0x00000000ffffffff) as i32,
    )
}

/// Host function trampolines.
/// Called from WASM modules to interact with the host.
mod local_host_func {
    use super::*;
    use crate::crypto::PublicKey;

    /// Get a slice from wasm memory at given offset and size.
    ///
    /// WARNING:
    /// This is very unsafe since it detaches the returned slice lifetime from
    /// the context that owns it. The trick works in the host functions because
    /// we know that the caller lives more than the returned slice.
    /// Unfortunately we had to do this to allow mutable borrow of the caller
    /// while we immutably owns the key. Again, safety of operation is
    /// guaranteed in this specific usage instances.
    fn slice_from(
        caller: impl AsContext,
        mem: &Memory,
        offset: i32,
        length: i32,
    ) -> std::result::Result<&[u8], Trap> {
        let data = unsafe {
            let len = mem.data_size(caller.as_context());
            let raw = mem.data_ptr(caller.as_context());
            slice::from_raw_parts(raw, len)
        };
        data.get(offset as usize..offset as usize + length as usize)
            .ok_or_else(|| Trap::new("out of bounds memory access"))
    }

    /// Get memory export from the caller.
    #[inline]
    fn mem_from(caller: &mut Caller<CallContext>) -> std::result::Result<Memory, Trap> {
        match caller.get_export("memory") {
            Some(Extern::Memory(mem)) => Ok(mem),
            _ => Err(Trap::new("failed to get caller's exported memory")),
        }
    }

    /// Returns the address of a slice pointing to a buffer allocated in wasm
    /// memory. This technique is used to return an array of bytes from host to
    /// the wasm.
    fn return_buf(
        mut caller: Caller<'_, CallContext>,
        mem: Memory,
        buf: Vec<u8>,
    ) -> std::result::Result<WasmSlice, Trap> {
        let alloc = caller
            .get_export("alloc")
            .and_then(|val| val.into_func())
            .ok_or_else(|| Trap::new("get `alloc` fail"))?;
        let alloc = alloc.typed::<i32, i32, StoreContext<CallContext>>(caller.as_context())?;

        // Copy the vector into wasm memory
        let offset = write_mem(&mut caller.as_context_mut(), &alloc, &mem, &buf)
            .map_err(|_err| Trap::new("error writing in wasm memory"))?;

        let wslice = wslice_create(offset, buf.len() as i32);
        Ok(wslice)
    }

    /// Logging facility for wasm code.
    fn log(
        mut caller: Caller<'_, CallContext>,
        offset: i32,
        size: i32,
    ) -> std::result::Result<(), Trap> {
        // Recover parameters from wasm memory.
        let mem: Memory = mem_from(&mut caller)?;
        let buf = slice_from(&mut caller, &mem, offset, size)?;
        let msg = String::from_utf8_lossy(buf);
        // Recover execution context.
        let ctx = caller.data();
        // Invoke portable host function.
        host_func::log(ctx, &msg);
        Ok(())
    }

    /// Load data from the account
    fn load_data(
        mut caller: Caller<'_, CallContext>,
        key_offset: i32,
        key_size: i32,
    ) -> std::result::Result<WasmSlice, Trap> {
        // Recover parameters from wasm memory.
        let mem: Memory = mem_from(&mut caller)?;
        let buf = slice_from(&mut caller, &mem, key_offset, key_size)?;
        let key = std::str::from_utf8(buf).map_err(|_| Trap::new("invalid utf-8"))?;
        // Recover execution context.
        let ctx = caller.data_mut();
        // Invoke portable host function.
        let buf = host_func::load_data(ctx, key);
        return_buf(caller, mem, buf)
    }

    /// Store contract data.
    fn store_data(
        mut caller: Caller<'_, CallContext>,
        key_offset: i32,
        key_size: i32,
        data_offset: i32,
        data_size: i32,
    ) -> std::result::Result<(), Trap> {
        // Recover parameters from wasm memory.
        let mem: Memory = mem_from(&mut caller)?;
        let buf = slice_from(&mut caller, &mem, key_offset, key_size)?;
        let key = std::str::from_utf8(buf).map_err(|_| Trap::new("invalid utf-8"))?;
        let data = slice_from(&mut caller, &mem, data_offset, data_size)?.to_owned();
        // Recover execution context.
        let ctx = caller.data_mut();
        // Invoke portable host fuction
        host_func::store_data(ctx, key, data);
        Ok(())
    }

    fn remove_data(
        mut caller: Caller<'_, CallContext>,
        key_offset: i32,
        key_size: i32,
    ) -> std::result::Result<(), Trap> {
        // Recover parameters from wasm memory.
        let mem: Memory = mem_from(&mut caller)?;
        let buf = slice_from(&mut caller, &mem, key_offset, key_size)?;
        let key = std::str::from_utf8(buf).map_err(|_| Trap::new("invalid utf-8"))?;
        // Recover execution context.
        let ctx = caller.data_mut();
        // Invoke portable host function.
        host_func::remove_data(ctx, key);
        Ok(())
    }

    /// Store asset data
    fn store_asset(
        mut caller: Caller<'_, CallContext>,
        account_id_offset: i32,
        account_id_length: i32,
        value_offset: i32,
        value_length: i32,
    ) -> std::result::Result<(), Trap> {
        // Recover parameters from wasm memory.
        let mem: Memory = mem_from(&mut caller)?;
        let buf = slice_from(&mut caller, &mem, account_id_offset, account_id_length)?;
        let account_id = String::from_utf8_lossy(buf);
        let value = slice_from(&mut caller, &mem, value_offset, value_length)?;
        // Recover execution context.
        let ctx = caller.data_mut();
        // Invoke portable host function.
        host_func::store_asset(ctx, &account_id, value);
        Ok(())
    }

    /// Load asset from the account
    fn load_asset(
        mut caller: Caller<'_, CallContext>,
        account_id_offset: i32,
        account_id_size: i32,
    ) -> std::result::Result<WasmSlice, Trap> {
        // Recover parameters from wasm memory.
        let mem: Memory = mem_from(&mut caller)?;
        let buf = slice_from(&mut caller, &mem, account_id_offset, account_id_size)?;
        let account_id = String::from_utf8_lossy(buf);
        // Recover execution context.
        let ctx = caller.data();
        // Invoke portable host function.
        let value = host_func::load_asset(ctx, &account_id);
        return_buf(caller, mem, value)
    }

    /// Digital signature verification.
    fn verify(
        mut caller: Caller<'_, CallContext>,
        pk_offset: i32,
        pk_length: i32,
        data_offset: i32,
        data_length: i32,
        sign_offset: i32,
        sign_length: i32,
    ) -> std::result::Result<i32, Trap> {
        // Recover parameters from wasm memory.
        let mem: Memory = mem_from(&mut caller)?;
        let pk = slice_from(&mut caller, &mem, pk_offset, pk_length)?;
        let pk: PublicKey = rmp_deserialize(pk).map_err(|_err| Trap::new("invalid public key"))?;
        let data = slice_from(&mut caller, &mem, data_offset, data_length)?;
        let sign = slice_from(&mut caller, &mem, sign_offset, sign_length)?;
        // Recover execution context.
        let ctx = caller.data_mut();
        // Invoke portable host function.
        Ok(host_func::verify(ctx, &pk, data, sign))
    }

    /// Call contract method.
    fn call(
        mut caller: Caller<'_, CallContext>,
        account_offset: i32,
        account_size: i32,
        method_offset: i32,
        method_size: i32,
        args_offset: i32,
        args_size: i32,
    ) -> std::result::Result<WasmSlice, Trap> {
        // Recover parameters from wasm memory.
        let mem: Memory = mem_from(&mut caller)?;
        let buf = slice_from(&mut caller, &mem, account_offset, account_size)?;
        let account = String::from_utf8_lossy(buf);
        let buf = slice_from(&mut caller, &mem, method_offset, method_size)?;
        let method = String::from_utf8_lossy(buf);
        let args = slice_from(&mut caller, &mem, args_offset, args_size)?;
        // Recover execution context.
        let ctx = caller.data_mut();
        // Invoke portable host function.
        let buf = match host_func::call(ctx, &account, &method, args) {
            Ok(buf) => rmp_serialize(&AppOutput {
                success: true,
                data: &buf,
            }),
            Err(err) => rmp_serialize(&AppOutput {
                success: false,
                data: err.to_string_full().as_bytes(),
            }),
        }
        .unwrap_or_default();
        return_buf(caller, mem, buf)
    }

    /// Register the required host functions using the same order as the wasm imports list.
    pub(crate) fn host_functions_register(
        mut store: &mut Store<CallContext>,
        module: &Module,
    ) -> Result<Vec<Extern>> {
        let mut imports: Vec<Extern> = Vec::new();
        let imports_list = module.imports();

        for import in imports_list {
            let func = match import.name().unwrap_or_default() {
                "hf_log" => Func::wrap(&mut store, log),
                "hf_load_data" => Func::wrap(&mut store, load_data),
                "hf_store_data" => Func::wrap(&mut store, store_data),
                "hf_remove_data" => Func::wrap(&mut store, remove_data),
                "hf_load_asset" => Func::wrap(&mut store, load_asset),
                "hf_store_asset" => Func::wrap(&mut store, store_asset),
                "hf_call" => Func::wrap(&mut store, call),
                "hf_verify" => Func::wrap(&mut store, verify),
                _ => {
                    return Err(Error::new_ext(
                        ErrorKind::NotImplemented,
                        "wasm import not found",
                    ))
                }
            };
            imports.push(func.into());
        }
        Ok(imports)
    }
}

/// Cached module.
/// Every time a smart contract is used the `last_used` field is updated.
/// When the cache is full and a new, non-cached, contract is required
/// to be loaded, the one with smaller unix time is removed.
struct CachedModule {
    /// Module instance.
    module: Module,
    /// Last used unix time.
    last_used: u64,
}

/// Closure trait to load a wasm binary.
pub trait WasmLoader: FnMut(Hash) -> Result<Vec<u8>> + Send + 'static {}

impl<T: FnMut(Hash) -> Result<Vec<u8>> + Send + 'static> WasmLoader for T {}

/// WebAssembly machine using wasmtime as the engine.
pub struct WmLocal {
    /// Global wasmtime context for compilation and management of wasm modules.
    engine: Engine,
    /// Callback to load wasm code.
    loader: Box<dyn WasmLoader>,
    /// Cached wasm modules, ready to be executed.
    cache: HashMap<Hash, CachedModule>,
    /// Maximum cache size.
    cache_max: usize,
}

impl WmLocal {
    /// Create a new WASM machine instance.
    ///
    /// # Panics
    ///
    /// Panics if the `cache_max` parameter is zero or if for any reason the
    /// backend fails to initialize.  Failure details are given in the `panic`
    /// error string.
    pub fn new(loader: impl WasmLoader, cache_max: usize) -> Self {
        assert!(
            !(cache_max == 0),
            "Fatal: Wm cache size shall be greater than 0"
        );

        let mut config = Config::default();
        config.interruptable(true);

        WmLocal {
            engine: Engine::new(&config).expect("wm engine creation"),
            loader: Box::new(loader),
            cache: HashMap::new(),
            cache_max,
        }
    }

    /// Caches a wasm using the user-provided callback.
    /// If the cache max size has been reached, it removes the least recently
    /// used module from the cache.
    fn load_module(&mut self, target: &Hash) -> Result<()> {
        let len = self.cache.len();
        if len > self.cache_max {
            let mut iter = self.cache.iter();
            // Safe: `cache_max` is guaranteed to be non-zero by construction.
            let mut older = iter.next().unwrap();
            for curr in iter {
                if curr.1.last_used < older.1.last_used {
                    older = curr;
                }
            }
            let older_hash = older.0.to_owned();
            self.cache.remove(&older_hash);
        }

        let wasm_bin = (self.loader)(*target)?;

        let module = Module::new(&self.engine, &wasm_bin)
            .map_err(|err| Error::new_ext(ErrorKind::Other, err))?;

        let entry = CachedModule {
            module,
            last_used: 0,
        };
        self.cache.insert(*target, entry);

        Ok(())
    }

    /// Get smart contract module instance from the cache.
    fn get_module(&mut self, target: &Hash) -> Result<&Module> {
        if !self.cache.contains_key(target) {
            self.load_module(target)?;
        }
        // This should not fail
        let mut entry = self
            .cache
            .get_mut(target)
            .expect("wasm module should have been loaded");
        // Update usage timestamp
        entry.last_used = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("read system time")
            .as_secs();
        Ok(&entry.module)
    }

    /// Allow to swap the loader after initialization.
    /// Loader switch flushes the cache.
    pub fn set_loader(&mut self, loader: impl WasmLoader) {
        self.loader = Box::new(loader);
        self.cache.clear();
    }
}

/// Allocate memory in the wasm and return a pointer to the module linear array memory
#[inline]
fn alloc_mem(
    store: &mut StoreContextMut<CallContext>,
    alloc: &TypedFunc<i32, i32>,
    size: i32,
) -> Result<i32> {
    alloc.call(store, size).map_err(|err| {
        error!("allocationg memory in the smart contract ({})", err);
        Error::new_ext(ErrorKind::WasmMachineFault, err)
    })
}

/// Allocate and write the serialized data in the wasm memory
fn write_mem(
    store: &mut StoreContextMut<CallContext>,
    alloc: &TypedFunc<i32, i32>,
    mem: &Memory,
    data: &[u8],
) -> Result<i32> {
    let length = data.len() as i32;
    let offset = alloc_mem(store, alloc, length)?;

    mem.write(store, offset as usize, data).map_err(|err| {
        error!(
            "writing data in wasm memory at address {:?} ({})",
            offset, err
        );
        Error::new_ext(ErrorKind::WasmMachineFault, err)
    })?;
    Ok(offset)
}

fn app_hash_check(db: &mut dyn DbFork, id: &str, mut app_hash: Option<Hash>) -> Result<Hash> {
    let mut updated = false;
    let account = match db.load_account(id) {
        Some(mut account) if account.contract != app_hash => {
            if account.contract.is_none() {
                account.contract = app_hash;
                updated = true;
            } else if app_hash.is_none() {
                app_hash = account.contract;
            } else {
                debug!("Invalid contract");
                return Err(Error::new_ext(
                    ErrorKind::ResourceNotFound,
                    "incompatible contract app",
                ));
            }
            account
        }
        Some(account) => account,
        None => {
            updated = true;
            Account::new(id, app_hash)
        }
    };
    let app_hash = app_hash.ok_or_else(|| {
        Error::new_ext(ErrorKind::ResourceNotFound, "smart contract not specified")
    })?;
    if updated {
        db.store_account(account);
    }
    Ok(app_hash)
}

impl Wm for WmLocal {
    /// Execute a smart contract.
    fn call(
        &mut self,
        db: &mut dyn DbFork,
        depth: u16,
        network: &str,
        origin: &str,
        owner: &str,
        caller: &str,
        contract: Option<Hash>,
        method: &str,
        args: &[u8],
    ) -> Result<Vec<u8>> {
        let app_hash = app_hash_check(db, owner, contract)?;

        // Prepare and set execution context for host functions.
        let ctx = CallContext {
            wm: None,
            db,
            owner,
            data_updated: false,
            depth,
            network,
            origin,
        };

        // Allocate execution context (aka Store).
        let mut store: Store<CallContext> = Store::new(&self.engine, ctx);

        // Get the requested wasm module instance.
        let module = self.get_module(&app_hash)?;

        // Get imported host functions list.
        let imports = local_host_func::host_functions_register(&mut store, module)?;

        // Instantiate the wasm module.
        let instance = Instance::new(&mut store, module, &imports)
            .map_err(|err| Error::new_ext(ErrorKind::WasmMachineFault, err))?;

        // Only at this point we can borrow `self` as mutable to set it as the
        // store data `ctx.wm` reference (replacing the dummy one).
        store.data_mut().wm = Some(self);

        // Get wasm allocator reference (this component is able to reserve
        // memory that lives within the wasm module).
        let alloc_func = instance
            .get_typed_func::<i32, i32, &mut Store<CallContext>>(&mut store, "alloc")
            .map_err(|_err| {
                error!("Function 'alloc' not found");
                Error::new_ext(ErrorKind::ResourceNotFound, "wasm `alloc` not found")
            })?;

        // Exporting the instance memory
        let mem = instance.get_memory(&mut store, "memory").ok_or_else(|| {
            error!("Expected 'memory' not found");
            Error::new_ext(ErrorKind::ResourceNotFound, "wasm `memory` not found")
        })?;

        // Write method arguments into wasm memory.
        let args_addr = write_mem(&mut store.as_context_mut(), &alloc_func, &mem, args)?;

        // Context information available to the wasm methods.
        let input = AppInput {
            owner,
            caller,
            method,
            depth,
            network,
            origin,
        };
        let input_buf = rmp_serialize(&input)?;
        let input_addr = write_mem(
            &mut store.as_context_mut(),
            &alloc_func,
            &mem,
            input_buf.as_ref(),
        )?;

        // Get function reference.
        let run_func = instance
            .get_typed_func::<(i32, i32, i32, i32), WasmSlice, StoreContextMut<CallContext>>(
                store.as_context_mut(),
                "run",
            )
            .map_err(|_err| {
                error!("Function `run` not found!");
                Error::new_ext(ErrorKind::ResourceNotFound, "wasm `run` not found")
            })?;

        // Wasm "run" function input parameters list.
        let params = (
            input_addr,
            input_buf.len() as i32,
            args_addr,
            args.len() as i32,
        );

        // Call smart contract entry point.
        let wslice = run_func
            .call(store.as_context_mut(), params)
            .map_err(|err| {
                // Here the error shall be serious and a probable crash of the wasm sandbox.
                Error::new_ext(ErrorKind::WasmMachineFault, err.to_string())
            })?;

        let ctx = store.data_mut();

        if ctx.data_updated {
            // Account data has been altered, update the `data_hash`.
            let mut account = ctx
                .db
                .load_account(ctx.owner)
                .ok_or_else(|| Error::new_ext(ErrorKind::WasmMachineFault, "inconsistent state"))?;
            account.data_hash = Some(ctx.db.state_hash(&account.id));
            ctx.db.store_account(account);
        }

        // Extract smart contract result from memory.
        let (offset, length) = wslice_split(wslice);
        let buf = mem
            .data(store.as_context())
            .get(offset as usize..offset as usize + length as usize)
            .ok_or_else(|| {
                Error::new_ext(ErrorKind::WasmMachineFault, "out of bounds memory access")
            })?;
        match rmp_deserialize::<AppOutput>(buf) {
            Ok(res) if res.success => Ok(res.data.to_owned()),
            Ok(res) => Err(Error::new_ext(
                ErrorKind::SmartContractFault,
                String::from_utf8_lossy(res.data),
            )),
            Err(err) => Err(Error::new_ext(ErrorKind::SmartContractFault, err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        base::serialize::rmp_serialize,
        crypto::{sign::tests::create_test_public_key, HashAlgorithm},
        wm::*,
        TransactionData,
    };
    use serde_value::{value, Value};

    const NOT_EXISTING_TARGET_HASH: &str =
        "12201810298b95a12ec9cde9210a81f2a7a5f0e4780da8d4a19b3b8346c0c684e12f";

    const CACHE_MAX: usize = 10;

    const TEST_WASM: &[u8] = include_bytes!("test.wasm");

    fn test_contract_hash() -> Hash {
        Hash::from_data(HashAlgorithm::Sha256, TEST_WASM)
    }

    impl WmLocal {
        fn exec_transaction<T: DbFork>(
            &mut self,
            db: &mut T,
            data: &TransactionData,
        ) -> Result<Vec<u8>> {
            self.call(
                db,
                0,
                "skynet",
                data.caller.to_account_id().as_str(),
                &data.account,
                data.caller.to_account_id().as_str(),
                data.contract,
                data.method.as_str(),
                &data.args,
            )
        }
    }

    fn wasm_loader(hash: Hash) -> Result<Vec<u8>> {
        if hash != test_contract_hash() {
            return Err(Error::new_ext(
                ErrorKind::ResourceNotFound,
                "wasm module not found",
            ));
        }
        Ok(TEST_WASM.to_owned())
    }

    fn create_test_db() -> MockDbFork {
        let mut db = MockDbFork::new();
        db.expect_load_account().returning(|id| {
            let app_hash = if id.eq("NotExistingTestId") {
                Hash::from_hex(NOT_EXISTING_TARGET_HASH).unwrap()
            } else {
                test_contract_hash()
            };
            let mut account = Account::new(id, Some(app_hash));
            account.store_asset(&account.id.clone(), 103_u64.to_be_bytes().as_ref());
            Some(account)
        });
        db.expect_store_account().returning(move |_id| ());
        db.expect_state_hash().returning(|_| Hash::default());
        db
    }

    fn create_test_data(method: &str, args: Value) -> TransactionData {
        let contract_hash = test_contract_hash();
        let public_key = create_test_public_key();
        let id = public_key.to_account_id();
        TransactionData {
            account: id,
            nonce: [0xab, 0x82, 0xb7, 0x41, 0xe0, 0x23, 0xa4, 0x12].to_vec(),
            network: "arya".to_string(),
            contract: Some(contract_hash), // Smart contract HASH
            method: method.to_string(),
            caller: public_key,
            args: rmp_serialize(&args).unwrap(),
        }
    }

    fn create_test_data_balance() -> TransactionData {
        create_test_data("balance", value!(null))
    }

    fn create_data_divide_by_zero() -> TransactionData {
        let args = value!({
            "zero": 0,
        });
        create_test_data("divide_by_zero", args)
    }

    fn create_test_data_transfer() -> TransactionData {
        let public_key = create_test_public_key();
        let from_id = public_key.to_account_id();
        let args = value!({
            "from": from_id,
            "to": from_id,
            "units": 11,
        });
        create_test_data("transfer", args)
    }

    #[test]
    fn instance_machine() {
        let mut vm = WmLocal::new(wasm_loader, CACHE_MAX);
        let hash = test_contract_hash();

        let result = vm.get_module(&hash);

        assert!(result.is_ok());
    }

    #[test]
    fn exec_transfer() {
        let mut vm = WmLocal::new(wasm_loader, CACHE_MAX);
        let data = create_test_data_transfer();
        let mut db = create_test_db();

        let buf = vm.exec_transaction(&mut db, &data).unwrap();

        let val: Value = rmp_deserialize(&buf).unwrap();
        assert_eq!(val, value!(null));
    }

    #[test]
    fn exec_balance() {
        let mut vm = WmLocal::new(wasm_loader, CACHE_MAX);
        let data = create_test_data_balance();
        let mut db = create_test_db();

        let buf = vm.exec_transaction(&mut db, &data).unwrap();

        let val: Value = rmp_deserialize(&buf).unwrap();
        assert_eq!(val, 103);
    }

    #[test]
    fn exec_balance_cached() {
        let mut vm = WmLocal::new(wasm_loader, CACHE_MAX);
        let data = create_test_data_balance();
        let mut db = create_test_db();
        vm.exec_transaction(&mut db, &data).unwrap();

        let buf = vm.exec_transaction(&mut db, &data).unwrap();

        let val: Value = rmp_deserialize(&buf).unwrap();
        assert_eq!(val, 103);
    }

    #[test]
    fn exec_inexistent_method() {
        let mut vm = WmLocal::new(wasm_loader, CACHE_MAX);
        let args = value!({});
        let data = create_test_data("inexistent", args);
        let mut db = create_test_db();

        let err = vm.exec_transaction(&mut db, &data).unwrap_err();

        assert_eq!(err.kind, ErrorKind::SmartContractFault);
        assert_eq!(
            err.to_string_full(),
            "smart contract fault: method `inexistent` not found"
        );
    }

    #[test]
    fn load_not_existing_module() {
        let mut vm = WmLocal::new(wasm_loader, CACHE_MAX);
        let mut data = create_test_data_transfer();
        data.contract = Some(Hash::from_hex(NOT_EXISTING_TARGET_HASH).unwrap());
        data.account = "NotExistingTestId".to_string();
        let mut db = create_test_db();

        let err = vm.exec_transaction(&mut db, &data).unwrap_err();

        assert_eq!(err.kind, ErrorKind::ResourceNotFound);
        assert_eq!(
            err.to_string_full(),
            "resource not found: wasm module not found"
        );
    }

    #[test]
    fn echo_generic() {
        let mut vm = WmLocal::new(wasm_loader, CACHE_MAX);
        let mut db = create_test_db();
        let input = value!({
            "name": "Davide",
            "surname": "Galassi",
            "buf": [[0x01, 0xFF, 0x80]],
            "vec8": [0x01_u8, 0xFF_u8, 0x80_u8],
            "vec16": [0x01_u8, 0xFFFF_u16, 0x8000_u16],
            "map": {
                "k1": { "field1": 123_u8, "field2": "foo" },
                "k2": { "field1": 456_u16, "field2": "bar" },
            },
        });
        let data = create_test_data("echo_generic", input.clone());

        let buf = vm.exec_transaction(&mut db, &data).unwrap();

        let output: Value = rmp_deserialize(&buf).unwrap();
        assert_eq!(input, output);
    }

    #[test]
    fn echo_typed() {
        let mut vm = WmLocal::new(wasm_loader, CACHE_MAX);
        let mut db = create_test_db();
        let input = value!({
            "name": "Davide",
            "surname": "Galassi",
            "buf": [[0x01, 0xFF, 0x80]],
            "vec8": [0x01_u8, 0xFF_u8, 0x80_u8],
            "vec16": [0x01_u8, 0xFFFF_u16, 0x8000_u16],
            "map": {
                "k1": { "field1": 123_u8, "field2": "foo" },
                "k2": { "field1": 456_u16, "field2": "bar" },
            },
        });
        let data = create_test_data("echo_typed", input.clone());

        let buf = vm.exec_transaction(&mut db, &data).unwrap();

        let output: Value = rmp_deserialize(&buf).unwrap();
        assert_eq!(input, output);
    }

    #[test]
    fn echo_typed_bad() {
        let mut vm = WmLocal::new(wasm_loader, CACHE_MAX);
        let mut db = create_test_db();
        let input = value!({
            "name": "Davide"
        });
        let data = create_test_data("echo_typed", input);

        let err = vm.exec_transaction(&mut db, &data).unwrap_err();

        assert_eq!(
            err.to_string_full(),
            "smart contract fault: deserialization failure"
        );
    }

    #[test]
    fn nested_call() {
        let mut vm = WmLocal::new(wasm_loader, CACHE_MAX);
        let mut db = create_test_db();
        let input = value!({
            "name": "Davide"
        });
        let data = create_test_data("nested_call", input.clone());

        let buf = vm.exec_transaction(&mut db, &data).unwrap();

        let output: Value = rmp_deserialize(&buf).unwrap();
        assert_eq!(input, output);
    }

    #[test]
    fn wasm_divide_by_zero() {
        let mut vm = WmLocal::new(wasm_loader, CACHE_MAX);
        let data = create_data_divide_by_zero();
        let mut db = create_test_db();

        let err = vm.exec_transaction(&mut db, &data).unwrap_err();

        let err_str = err.to_string_full();
        let err_str = err_str.split_inclusive("trap").next().unwrap();
        assert_eq!(err_str, "wasm machine fault: wasm trap");
    }

    #[test]
    fn wasm_trigger_panic() {
        let mut vm = WmLocal::new(wasm_loader, CACHE_MAX);
        let data = create_test_data("trigger_panic", value!(null));
        let mut db = create_test_db();

        let err = vm.exec_transaction(&mut db, &data).unwrap_err();

        let err_str = err.to_string_full();
        let err_str = err_str.split_inclusive("trap").next().unwrap();
        assert_eq!(err_str, "wasm machine fault: wasm trap");
    }

    #[test]
    fn wasm_exhaust_memory() {
        let mut vm = WmLocal::new(wasm_loader, CACHE_MAX);
        let data = create_test_data("exhaust_memory", value!(null));
        let mut db = create_test_db();

        let err = vm.exec_transaction(&mut db, &data).unwrap_err();

        let err_str = err.to_string_full();
        let err_str = err_str.split_inclusive("range").next().unwrap();
        assert_eq!(err_str, "wasm machine fault: out of bounds memory access");
    }

    #[test]
    fn wasm_infinite_recursion() {
        let mut vm = WmLocal::new(wasm_loader, CACHE_MAX);
        let data = create_test_data("infinite_recursion", value!(true));
        let mut db = create_test_db();

        let err = vm.exec_transaction(&mut db, &data).unwrap_err();

        let err_str = err.to_string_full();
        let err_str = err_str.split_inclusive("exhausted").next().unwrap();
        assert_eq!(
            err_str,
            "wasm machine fault: wasm trap: call stack exhausted"
        );
    }

    // Need to be handle with an interrupt_handle
    // https://docs.rs/wasmtime/0.26.0/wasmtime/struct.Store.html#method.interrupt_handle
    #[test]
    #[ignore = "TODO"]
    fn wasm_infinite_loop() {
        let mut vm = WmLocal::new(wasm_loader, CACHE_MAX);
        let data = create_test_data("infinite_loop", value!(null));
        let mut db = create_test_db();

        let err = vm.exec_transaction(&mut db, &data).unwrap_err();

        let err_str = err.to_string_full();
        let err_str = err_str.split_inclusive("access").next().unwrap();
        assert_eq!(err_str, "TODO");
    }

    #[test]
    fn wasm_null_pointer_indirection() {
        let mut vm = WmLocal::new(wasm_loader, CACHE_MAX);
        let data = create_test_data("null_pointer_indirection", value!(null));
        let mut db = create_test_db();

        let err = vm.exec_transaction(&mut db, &data).unwrap_err();

        let err_str = err.to_string_full();
        let err_str = err_str.split_inclusive("unreachable").next().unwrap();
        assert_eq!(err_str, "wasm machine fault: wasm trap: unreachable");
    }

    #[test]
    #[ignore]
    fn analyze_wasm_default_module() {
        println!("Contract Hash: {}", hex::encode(test_contract_hash()));

        let store: Store<()> = Store::default();
        let module = Module::new(store.engine(), TEST_WASM).unwrap();

        println!("Checking the module exports...");
        let exports = module.exports();
        println!("Esports No. {}", exports.len());
        for export in exports {
            println!(">> {:#?}", export);
        }

        let t_imp = module.imports();
        println!("Imports No. {}", t_imp.len());
        for imp in t_imp {
            println!(">> {:#?}", imp);
        }
    }
}
