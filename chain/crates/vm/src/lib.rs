//! # sov-vm
//!
//! SOV's smart-contract runtime: a WebAssembly virtual machine built on the
//! pure-Rust [`wasmi`] interpreter. Two properties make it the right base for a
//! sovereign chain:
//!
//! - **Deterministic** — an interpreter (no JIT) executes identically on every
//!   node and platform, so consensus never diverges over a contract's result.
//! - **Portable** — pure Rust with no native codegen, so the same VM runs on the
//!   macOS, Windows, and Linux clients.
//!
//! Execution is **gas-metered** via wasmi fuel: every contract call is given a
//! budget, each Wasm operation consumes fuel, and a contract that exceeds its
//! budget traps with [`VmError::OutOfGas`] rather than running unbounded.
//! Contracts interact with the chain only through a small, explicit host ABI
//! (module `env`). ABI v2: read/write their [`ContractStorage`]; read block
//! height, calldata, the authenticated caller, and their own address; set
//! bounded return data; emit bounded events; query and spend **their own**
//! native-asset balances via `token_balance`/`token_transfer` (queued commands
//! the runtime re-validates and commits atomically). There is no ambient
//! authority — a contract can touch nothing the host did not hand it.

#![forbid(unsafe_code)]

mod storage;

pub use storage::ContractStorage;

use std::collections::BTreeMap;

use wasmi::{Caller, Config, Engine, Linker, Module, Store};

/// Block/transaction context exposed to a contract during execution (ABI v2).
///
/// The VM is **ledger-agnostic**: it never sees the chain's `Ledger`. The
/// runtime materializes everything a call may observe — including the
/// contract's *own* token balances — into this context up front, and the VM
/// hands back the call's effects (storage, return data, events, token-transfer
/// commands) for the runtime to validate and commit. A contract can therefore
/// never read or move state the host did not explicitly hand it.
#[derive(Clone, Debug, Default)]
pub struct ExecContext {
    /// Height of the block this call executes in.
    pub block_height: u64,
    /// The account that signed the transaction invoking this call. Exposed via
    /// the `caller` host function — authenticated identity (the runtime only
    /// sets it after signature and key checks), not a free-form claim.
    pub caller: String,
    /// The contract's own account id (the callee).
    pub contract: String,
    /// Opaque input bytes from the transaction (bounded by BIP-110 upstream).
    pub calldata: Vec<u8>,
    /// The contract's own native-asset balances, keyed by the 32-byte asset id.
    /// This is the *only* token state a contract can observe or spend.
    pub token_balances: BTreeMap<[u8; 32], u128>,
}

/// An event a contract emitted during a call (bounded; recorded in the
/// transaction receipt and therefore committed under `receipts_root`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmEvent {
    /// The event's topic (≤ [`MAX_EVENT_TOPIC_BYTES`] bytes).
    pub topic: Vec<u8>,
    /// The event's payload (≤ [`MAX_EVENT_DATA_BYTES`] bytes).
    pub data: Vec<u8>,
}

/// A token-transfer command a contract queued during a call: move `amount`
/// units of `asset` from the **contract's own balance** to `to`. The VM
/// pre-validates each command against the materialized working copy (so a
/// contract cannot overspend in-VM); the runtime re-validates against the real
/// ledger with checked arithmetic before committing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenTransferCmd {
    /// The 32-byte asset id.
    pub asset: [u8; 32],
    /// The recipient account id (utf-8; validated as an `AccountId` upstream).
    pub to: String,
    /// Units to move.
    pub amount: u128,
}

/// The result of a successful contract call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmOutcome {
    /// The `i32` status the contract's entry point returned.
    pub status: i32,
    /// Gas (wasmi fuel) consumed by the call.
    pub gas_used: u64,
    /// Bytes the contract set via `set_return` (≤ [`MAX_RETURN_BYTES`]).
    pub return_data: Vec<u8>,
    /// Events the contract emitted, in emission order.
    pub events: Vec<VmEvent>,
    /// Token-transfer commands the contract queued, in order. Already
    /// debit-validated against the materialized balances; the runtime applies
    /// them to the ledger only if the whole action commits.
    pub token_transfers: Vec<TokenTransferCmd>,
}

/// Errors from compiling or running a contract.
#[derive(Debug, thiserror::Error)]
pub enum VmError {
    /// The Wasm bytes failed to compile/validate.
    #[error("contract failed to compile: {0}")]
    Compile(String),
    /// The module could not be instantiated (e.g. unsatisfied imports).
    #[error("contract failed to instantiate: {0}")]
    Instantiate(String),
    /// The requested entry point export was missing or had the wrong signature.
    #[error("entry point '{0}' not found or has the wrong signature")]
    MissingEntry(String),
    /// The contract exhausted its gas budget.
    #[error("contract ran out of gas")]
    OutOfGas,
    /// The contract trapped during execution.
    #[error("contract trapped: {0}")]
    Trap(String),
}

/// Maximum bytes a contract storage key may occupy.
const MAX_STORAGE_KEY_BYTES: usize = 1024;
/// Maximum bytes a contract storage value may occupy.
const MAX_STORAGE_VALUE_BYTES: usize = 64 * 1024;
/// Maximum total bytes (keys + values) a single call may write to storage, so
/// committed state growth is bounded and priced per call — not merely capped by
/// the wasmi fuel limit.
const MAX_CALL_STORAGE_BYTES: usize = 1024 * 1024;
/// Maximum bytes a contract may set as its return data.
pub const MAX_RETURN_BYTES: usize = 64 * 1024;
/// Maximum number of events one call may emit.
pub const MAX_EVENTS_PER_CALL: usize = 64;
/// Maximum bytes of an event topic.
pub const MAX_EVENT_TOPIC_BYTES: usize = 64;
/// Maximum bytes of an event payload.
pub const MAX_EVENT_DATA_BYTES: usize = 1024;
/// Maximum token-transfer commands one call may queue.
pub const MAX_TOKEN_TRANSFERS_PER_CALL: usize = 128;
/// Maximum bytes of a recipient account id passed to `token_transfer`.
const MAX_ACCOUNT_ID_BYTES: usize = 64;

/// Host state available to the contract's imported functions.
struct HostState {
    storage: ContractStorage,
    ctx: ExecContext,
    /// Remaining bytes this call may still write to storage.
    write_budget: usize,
    /// Working copy of the contract's token balances: every queued transfer is
    /// debited here first, so a contract can never overspend within one call.
    token_balances: BTreeMap<[u8; 32], u128>,
    /// Return data set by the contract (last `set_return` wins).
    return_data: Vec<u8>,
    /// Events emitted so far.
    events: Vec<VmEvent>,
    /// Token-transfer commands queued so far.
    token_transfers: Vec<TokenTransferCmd>,
}

/// Fetch the contract's exported linear memory from within a host function.
fn memory(caller: &mut Caller<'_, HostState>) -> Result<wasmi::Memory, wasmi::Error> {
    caller
        .get_export("memory")
        .and_then(wasmi::Extern::into_memory)
        .ok_or_else(|| wasmi::Error::new("contract has no exported 'memory'"))
}

/// Maximum bytes a single host-ABI call will read from guest memory — bounds the
/// allocation a contract can induce, independent of fuel metering.
const MAX_HOST_READ_BYTES: usize = 1 << 20; // 1 MiB

/// Read `len` bytes at `ptr` from the contract's memory. Rejects negative or
/// oversized lengths and verifies the range is in bounds **before** allocating,
/// so a bogus guest length cannot induce a huge allocation (an OOM outside fuel
/// metering) — the buffer is only ever as large as a validated, in-range request.
fn read_bytes(
    caller: &Caller<'_, HostState>,
    mem: &wasmi::Memory,
    ptr: i32,
    len: i32,
) -> Result<Vec<u8>, wasmi::Error> {
    if ptr < 0 || len < 0 {
        return Err(wasmi::Error::new("negative pointer or length"));
    }
    let (ptr, len) = (ptr as usize, len as usize);
    if len > MAX_HOST_READ_BYTES {
        return Err(wasmi::Error::new("host read exceeds maximum size"));
    }
    let mem_len = mem.data(caller).len();
    if ptr.checked_add(len).is_none_or(|end| end > mem_len) {
        return Err(wasmi::Error::new("memory read out of bounds"));
    }
    let mut buf = vec![0u8; len];
    mem.read(caller, ptr, &mut buf)
        .map_err(|_| wasmi::Error::new("memory read out of bounds"))?;
    Ok(buf)
}

/// Register the host ABI (module `env`) on `linker`.
fn install_host_abi(linker: &mut Linker<HostState>) -> Result<(), wasmi::Error> {
    // storage_write(key_ptr, key_len, val_ptr, val_len)
    linker.func_wrap(
        "env",
        "storage_write",
        |mut caller: Caller<'_, HostState>,
         kp: i32,
         kl: i32,
         vp: i32,
         vl: i32|
         -> Result<(), wasmi::Error> {
            let mem = memory(&mut caller)?;
            let key = read_bytes(&caller, &mem, kp, kl)?;
            let val = read_bytes(&caller, &mem, vp, vl)?;
            // Bound and price committed storage: per-entry size caps plus a
            // per-call total-bytes budget, charged before the write commits.
            if key.len() > MAX_STORAGE_KEY_BYTES {
                return Err(wasmi::Error::new("storage key exceeds maximum size"));
            }
            if val.len() > MAX_STORAGE_VALUE_BYTES {
                return Err(wasmi::Error::new("storage value exceeds maximum size"));
            }
            let cost = key.len() + val.len();
            let st = caller.data_mut();
            st.write_budget = st
                .write_budget
                .checked_sub(cost)
                .ok_or_else(|| wasmi::Error::new("call storage-write budget exceeded"))?;
            st.storage.set(key, val);
            Ok(())
        },
    )?;

    // storage_read(key_ptr, key_len, out_ptr, out_cap) -> i32
    // Returns the value's full length (-1 if absent); writes up to out_cap bytes.
    linker.func_wrap(
        "env",
        "storage_read",
        |mut caller: Caller<'_, HostState>,
         kp: i32,
         kl: i32,
         op: i32,
         cap: i32|
         -> Result<i32, wasmi::Error> {
            let mem = memory(&mut caller)?;
            let key = read_bytes(&caller, &mem, kp, kl)?;
            match caller.data().storage.get(&key).map(<[u8]>::to_vec) {
                Some(value) => {
                    let n = value.len().min(cap.max(0) as usize);
                    mem.write(&mut caller, op as usize, &value[..n])
                        .map_err(|_| wasmi::Error::new("memory write out of bounds"))?;
                    Ok(value.len() as i32)
                }
                None => Ok(-1),
            }
        },
    )?;

    // block_height() -> i64
    linker.func_wrap(
        "env",
        "block_height",
        |caller: Caller<'_, HostState>| -> i64 { caller.data().ctx.block_height as i64 },
    )?;

    // calldata(out_ptr, out_cap) -> i32
    // Returns the calldata's full length; writes up to out_cap bytes of it.
    // (Call with out_cap = 0 to query the length.) Same convention as
    // storage_read, so guests size their buffer with one extra call.
    linker.func_wrap(
        "env",
        "calldata",
        |mut caller: Caller<'_, HostState>, op: i32, cap: i32| -> Result<i32, wasmi::Error> {
            let mem = memory(&mut caller)?;
            let data = caller.data().ctx.calldata.clone();
            write_out(&mut caller, &mem, op, cap, &data)
        },
    )?;

    // caller(out_ptr, out_cap) -> i32
    // The authenticated signer of the invoking transaction (utf-8 account id).
    // Returns its full length; writes up to out_cap bytes.
    linker.func_wrap(
        "env",
        "caller",
        |mut caller: Caller<'_, HostState>, op: i32, cap: i32| -> Result<i32, wasmi::Error> {
            let mem = memory(&mut caller)?;
            let id = caller.data().ctx.caller.clone().into_bytes();
            write_out(&mut caller, &mem, op, cap, &id)
        },
    )?;

    // address(out_ptr, out_cap) -> i32
    // The contract's own account id (utf-8). Same convention as `caller`.
    linker.func_wrap(
        "env",
        "address",
        |mut caller: Caller<'_, HostState>, op: i32, cap: i32| -> Result<i32, wasmi::Error> {
            let mem = memory(&mut caller)?;
            let id = caller.data().ctx.contract.clone().into_bytes();
            write_out(&mut caller, &mem, op, cap, &id)
        },
    )?;

    // set_return(ptr, len)
    // Set the call's return data (bounded; the last call wins).
    linker.func_wrap(
        "env",
        "set_return",
        |mut caller: Caller<'_, HostState>, p: i32, l: i32| -> Result<(), wasmi::Error> {
            let mem = memory(&mut caller)?;
            let data = read_bytes(&caller, &mem, p, l)?;
            if data.len() > MAX_RETURN_BYTES {
                return Err(wasmi::Error::new("return data exceeds maximum size"));
            }
            caller.data_mut().return_data = data;
            Ok(())
        },
    )?;

    // emit(topic_ptr, topic_len, data_ptr, data_len)
    // Emit one bounded event, recorded in the transaction receipt.
    linker.func_wrap(
        "env",
        "emit",
        |mut caller: Caller<'_, HostState>,
         tp: i32,
         tl: i32,
         dp: i32,
         dl: i32|
         -> Result<(), wasmi::Error> {
            let mem = memory(&mut caller)?;
            let topic = read_bytes(&caller, &mem, tp, tl)?;
            let data = read_bytes(&caller, &mem, dp, dl)?;
            if topic.len() > MAX_EVENT_TOPIC_BYTES {
                return Err(wasmi::Error::new("event topic exceeds maximum size"));
            }
            if data.len() > MAX_EVENT_DATA_BYTES {
                return Err(wasmi::Error::new("event data exceeds maximum size"));
            }
            let st = caller.data_mut();
            if st.events.len() >= MAX_EVENTS_PER_CALL {
                return Err(wasmi::Error::new("too many events in one call"));
            }
            st.events.push(VmEvent { topic, data });
            Ok(())
        },
    )?;

    // token_balance(asset_ptr, out_ptr) -> i32
    // Write the contract's OWN balance of the 32-byte asset at `asset_ptr` as
    // 16 little-endian bytes at `out_ptr`. Absent assets read as zero.
    linker.func_wrap(
        "env",
        "token_balance",
        |mut caller: Caller<'_, HostState>, ap: i32, op: i32| -> Result<i32, wasmi::Error> {
            let mem = memory(&mut caller)?;
            let asset: [u8; 32] = read_bytes(&caller, &mem, ap, 32)?
                .try_into()
                .expect("read_bytes returned exactly 32 bytes");
            let balance = caller
                .data()
                .token_balances
                .get(&asset)
                .copied()
                .unwrap_or(0);
            mem.write(&mut caller, op.max(0) as usize, &balance.to_le_bytes())
                .map_err(|_| wasmi::Error::new("memory write out of bounds"))?;
            Ok(0)
        },
    )?;

    // token_transfer(asset_ptr, to_ptr, to_len, amount_ptr) -> i32
    // Queue a transfer of `amount` (16 LE bytes at `amount_ptr`) units of the
    // asset at `asset_ptr` from the contract's own balance to the account id at
    // `to_ptr`. Returns 0 and debits the working balance on success; returns -1
    // if the contract's balance is insufficient (a contract can branch on it).
    // Malformed inputs and exceeding the per-call command cap trap.
    linker.func_wrap(
        "env",
        "token_transfer",
        |mut caller: Caller<'_, HostState>,
         ap: i32,
         top: i32,
         tol: i32,
         amp: i32|
         -> Result<i32, wasmi::Error> {
            let mem = memory(&mut caller)?;
            let asset: [u8; 32] = read_bytes(&caller, &mem, ap, 32)?
                .try_into()
                .expect("read_bytes returned exactly 32 bytes");
            let to = read_bytes(&caller, &mem, top, tol)?;
            if to.is_empty() || to.len() > MAX_ACCOUNT_ID_BYTES {
                return Err(wasmi::Error::new("recipient account id has invalid length"));
            }
            let to = String::from_utf8(to)
                .map_err(|_| wasmi::Error::new("recipient account id is not utf-8"))?;
            let amount = u128::from_le_bytes(
                read_bytes(&caller, &mem, amp, 16)?
                    .try_into()
                    .expect("read_bytes returned exactly 16 bytes"),
            );
            let st = caller.data_mut();
            if st.token_transfers.len() >= MAX_TOKEN_TRANSFERS_PER_CALL {
                return Err(wasmi::Error::new("too many token transfers in one call"));
            }
            // Debit the working copy first: insufficient funds is a graceful
            // -1, and a contract can never queue an overspend. A self-transfer
            // nets to zero, so the observable balance is left unchanged —
            // matching what the runtime will commit.
            let balance = st.token_balances.get(&asset).copied().unwrap_or(0);
            let Some(remaining) = balance.checked_sub(amount) else {
                return Ok(-1);
            };
            if to != st.ctx.contract {
                st.token_balances.insert(asset, remaining);
            }
            st.token_transfers
                .push(TokenTransferCmd { asset, to, amount });
            Ok(0)
        },
    )?;

    Ok(())
}

/// Write `data` (up to `cap` bytes of it) into guest memory at `op`, returning
/// `data`'s full length — the shared out-buffer convention of the read-style
/// host functions (`storage_read`, `calldata`, `caller`, `address`).
fn write_out(
    caller: &mut Caller<'_, HostState>,
    mem: &wasmi::Memory,
    op: i32,
    cap: i32,
    data: &[u8],
) -> Result<i32, wasmi::Error> {
    let n = data.len().min(cap.max(0) as usize);
    mem.write(caller, op.max(0) as usize, &data[..n])
        .map_err(|_| wasmi::Error::new("memory write out of bounds"))?;
    Ok(data.len() as i32)
}

/// Execute contract `wasm`, calling its `entry` export (signature `() -> i32`)
/// with a `gas_limit`. Storage mutations are committed to `storage` only if the
/// call succeeds — a trapped or out-of-gas call leaves `storage` untouched.
pub fn execute(
    wasm: &[u8],
    entry: &str,
    gas_limit: u64,
    ctx: ExecContext,
    storage: &mut ContractStorage,
) -> Result<VmOutcome, VmError> {
    let mut config = Config::default();
    config.consume_fuel(true);
    let engine = Engine::new(&config);

    let module = Module::new(&engine, wasm).map_err(|e| VmError::Compile(e.to_string()))?;

    // Run against a clone so failures don't partially mutate committed state.
    let token_balances = ctx.token_balances.clone();
    let mut store = Store::new(
        &engine,
        HostState {
            storage: storage.clone(),
            ctx,
            write_budget: MAX_CALL_STORAGE_BYTES,
            token_balances,
            return_data: Vec::new(),
            events: Vec::new(),
            token_transfers: Vec::new(),
        },
    );
    store
        .set_fuel(gas_limit)
        .map_err(|e| VmError::Trap(e.to_string()))?;

    let mut linker = Linker::new(&engine);
    install_host_abi(&mut linker).map_err(|e| VmError::Instantiate(e.to_string()))?;
    let instance = linker
        .instantiate_and_start(&mut store, &module)
        .map_err(|e| VmError::Instantiate(e.to_string()))?;

    let func = instance
        .get_typed_func::<(), i32>(&store, entry)
        .map_err(|_| VmError::MissingEntry(entry.to_string()))?;

    match func.call(&mut store, ()) {
        Ok(status) => {
            let gas_used = gas_limit.saturating_sub(store.get_fuel().unwrap_or(0));
            let state = store.into_data();
            *storage = state.storage; // commit on success
            Ok(VmOutcome {
                status,
                gas_used,
                return_data: state.return_data,
                events: state.events,
                token_transfers: state.token_transfers,
            })
        }
        Err(err) => {
            // Distinguish a gas-exhaustion trap from any other trap.
            if err.as_trap_code() == Some(wasmi::TrapCode::OutOfFuel) {
                Err(VmError::OutOfGas)
            } else {
                Err(VmError::Trap(err.to_string()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compile(wat: &str) -> Vec<u8> {
        wat::parse_str(wat).expect("valid wat")
    }

    fn ctx() -> ExecContext {
        ExecContext::default()
    }

    #[test]
    fn oversized_storage_key_is_rejected() {
        // R-04: a storage key over the protocol cap traps cleanly, bounding
        // committed state growth rather than relying on fuel alone.
        let wasm = compile(
            r#"(module
                (import "env" "storage_write" (func $sw (param i32 i32 i32 i32)))
                (memory (export "memory") 1)
                (func (export "run") (result i32)
                    (call $sw (i32.const 0) (i32.const 2000) (i32.const 0) (i32.const 1))
                    (i32.const 0)))"#,
        );
        let mut storage = ContractStorage::new();
        assert!(
            execute(&wasm, "run", 10_000_000, ctx(), &mut storage).is_err(),
            "an over-cap storage key must trap, not commit"
        );
    }

    #[test]
    fn rejects_oversized_host_read() {
        // A contract that asks the host to read ~2 GiB must trap cleanly rather
        // than attempt the allocation (which would OOM a validator, outside fuel).
        let wasm = compile(
            r#"(module
                (import "env" "storage_write" (func $sw (param i32 i32 i32 i32)))
                (memory (export "memory") 1)
                (func (export "run") (result i32)
                    (call $sw (i32.const 0) (i32.const 2000000000) (i32.const 0) (i32.const 0))
                    (i32.const 0)))"#,
        );
        let mut storage = ContractStorage::new();
        assert!(
            execute(&wasm, "run", 10_000_000, ctx(), &mut storage).is_err(),
            "an out-of-range host-read length must trap, not allocate"
        );
    }

    #[test]
    fn contract_writes_and_reads_storage() {
        let wasm = compile(
            r#"(module
                (import "env" "storage_write" (func $sw (param i32 i32 i32 i32)))
                (import "env" "storage_read" (func $sr (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "key")
                (data (i32.const 16) "value")
                (func (export "run") (result i32)
                    (call $sw (i32.const 0) (i32.const 3) (i32.const 16) (i32.const 5))
                    (call $sr (i32.const 0) (i32.const 3) (i32.const 64) (i32.const 32))))"#,
        );
        let mut storage = ContractStorage::new();
        let outcome = execute(&wasm, "run", 10_000_000, ctx(), &mut storage).unwrap();
        // The read returns the value's length (5)...
        assert_eq!(outcome.status, 5);
        assert!(outcome.gas_used > 0);
        // ...and the write was committed.
        assert_eq!(storage.get(b"key"), Some(&b"value"[..]));
    }

    #[test]
    fn block_height_is_exposed() {
        let wasm = compile(
            r#"(module
                (import "env" "block_height" (func $bh (result i64)))
                (memory (export "memory") 1)
                (func (export "run") (result i32)
                    (i32.wrap_i64 (call $bh))))"#,
        );
        let mut storage = ContractStorage::new();
        let outcome = execute(
            &wasm,
            "run",
            1_000_000,
            ExecContext {
                block_height: 42,
                ..ExecContext::default()
            },
            &mut storage,
        )
        .unwrap();
        assert_eq!(outcome.status, 42);
    }

    #[test]
    fn out_of_gas_traps_and_does_not_commit() {
        // An unbounded loop that also writes storage before looping forever.
        let wasm = compile(
            r#"(module
                (import "env" "storage_write" (func $sw (param i32 i32 i32 i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "k")
                (func (export "run") (result i32)
                    (call $sw (i32.const 0) (i32.const 1) (i32.const 0) (i32.const 1))
                    (loop $l (br $l))
                    (i32.const 0)))"#,
        );
        let mut storage = ContractStorage::new();
        let err = execute(&wasm, "run", 100_000, ctx(), &mut storage).unwrap_err();
        assert!(matches!(err, VmError::OutOfGas));
        // The trapped call must not have committed its write.
        assert!(storage.is_empty());
    }

    #[test]
    fn token_balance_reads_the_materialized_balance_and_overspend_is_minus_one() {
        // Asset id = the 32 zero bytes at offset 0 of the contract's fresh
        // memory; recipient "x.sov" at 64; amount (16 LE bytes) at 96. The
        // contract: tries to transfer 600 (> 500 balance) -> -1; transfers
        // 200 -> 0; returns the remaining balance's low 32 bits (300).
        let wasm = compile(
            r#"(module
                (import "env" "token_balance" (func $tb (param i32 i32) (result i32)))
                (import "env" "token_transfer" (func $tt (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 64) "x.sov")
                (func (export "run") (result i32)
                    ;; amount = 600 at 96
                    (i64.store (i32.const 96) (i64.const 600))
                    (i64.store (i32.const 104) (i64.const 0))
                    ;; overspend must be -1
                    (if (i32.ne (call $tt (i32.const 0) (i32.const 64) (i32.const 5) (i32.const 96)) (i32.const -1))
                        (then (unreachable)))
                    ;; amount = 200
                    (i64.store (i32.const 96) (i64.const 200))
                    (if (i32.ne (call $tt (i32.const 0) (i32.const 64) (i32.const 5) (i32.const 96)) (i32.const 0))
                        (then (unreachable)))
                    ;; remaining balance -> 16 LE bytes at 128
                    (drop (call $tb (i32.const 0) (i32.const 128)))
                    (i32.load (i32.const 128))))"#,
        );
        let mut storage = ContractStorage::new();
        // The asset-id bytes the contract passes are whatever sits at offset 0
        // of its zero-initialized memory — so key the balance on 32 zero bytes.
        let mut token_balances = BTreeMap::new();
        token_balances.insert([0u8; 32], 500u128);
        let outcome = execute(
            &wasm,
            "run",
            10_000_000,
            ExecContext {
                token_balances,
                contract: "treasury.sov".into(),
                ..ExecContext::default()
            },
            &mut storage,
        )
        .unwrap();
        assert_eq!(outcome.status, 300, "balance after the 200-unit transfer");
        assert_eq!(outcome.token_transfers.len(), 1);
        assert_eq!(
            outcome.token_transfers[0],
            TokenTransferCmd {
                asset: [0u8; 32],
                to: "x.sov".into(),
                amount: 200,
            }
        );
    }

    #[test]
    fn event_count_is_capped() {
        // Emitting more than MAX_EVENTS_PER_CALL events must trap, and a
        // trapped call commits nothing.
        let wasm = compile(
            r#"(module
                (import "env" "emit" (func $em (param i32 i32 i32 i32)))
                (memory (export "memory") 1)
                (func (export "run") (result i32)
                    (local $i i32)
                    (loop $l
                        (call $em (i32.const 0) (i32.const 4) (i32.const 8) (i32.const 4))
                        (local.set $i (i32.add (local.get $i) (i32.const 1)))
                        (br_if $l (i32.lt_u (local.get $i) (i32.const 100))))
                    (i32.const 0)))"#,
        );
        let mut storage = ContractStorage::new();
        let err = execute(&wasm, "run", 10_000_000, ctx(), &mut storage).unwrap_err();
        assert!(matches!(err, VmError::Trap(_)), "got: {err:?}");
    }

    #[test]
    fn missing_entry_point_is_reported() {
        let wasm = compile(r#"(module (func (export "run") (result i32) (i32.const 1)))"#);
        let mut storage = ContractStorage::new();
        let err = execute(&wasm, "nope", 1_000_000, ctx(), &mut storage).unwrap_err();
        assert!(matches!(err, VmError::MissingEntry(_)));
    }

    #[test]
    fn invalid_wasm_fails_to_compile() {
        let mut storage = ContractStorage::new();
        let err = execute(&[0, 1, 2, 3], "run", 1_000_000, ctx(), &mut storage).unwrap_err();
        assert!(matches!(err, VmError::Compile(_)));
    }
}
