//! # sov-sdk — the guest SDK for writing SOV smart contracts in Rust.
//!
//! A contract is a `no_std` crate compiled to `wasm32-unknown-unknown` that
//! depends on this SDK and exports `call() -> i32`. The SDK provides:
//!
//! - safe wrappers over the host ABI (the `env` module the `sov-vm` runtime
//!   links): [`get`], [`set`], [`current_height`];
//! - a tiny bump allocator (contracts are single-shot, so allocation never needs
//!   to free); and
//! - a panic handler that traps the VM.
//!
//! `unsafe` is unavoidable here — FFI to the host and raw pointer marshaling are
//! inherently unsafe — but it is confined to this crate so contract authors
//! write only safe Rust.

#![no_std]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;

// ----- Host ABI: the `env` functions the sov-vm runtime provides. -----
extern "C" {
    fn storage_write(key_ptr: i32, key_len: i32, val_ptr: i32, val_len: i32);
    fn storage_read(key_ptr: i32, key_len: i32, out_ptr: i32, out_cap: i32) -> i32;
    fn block_height() -> i64;
}

/// Write `value` at `key` in the contract's storage.
pub fn set(key: &[u8], value: &[u8]) {
    // SAFETY: pointers/lengths describe live slices in this module's memory.
    unsafe {
        storage_write(
            key.as_ptr() as i32,
            key.len() as i32,
            value.as_ptr() as i32,
            value.len() as i32,
        );
    }
}

/// Read the value at `key`, or `None` if unset.
pub fn get(key: &[u8]) -> Option<Vec<u8>> {
    // SAFETY: first probe (cap 0) returns the value length without writing;
    // the second call fills an exactly-sized buffer.
    unsafe {
        let len = storage_read(key.as_ptr() as i32, key.len() as i32, 0, 0);
        if len < 0 {
            return None;
        }
        let mut buf = vec![0u8; len as usize];
        storage_read(key.as_ptr() as i32, key.len() as i32, buf.as_mut_ptr() as i32, len);
        Some(buf)
    }
}

/// The height of the block this call is executing in.
pub fn current_height() -> u64 {
    // SAFETY: a plain host call returning a scalar.
    unsafe { block_height() as u64 }
}

// ----- Runtime support: bump allocator + panic handler. -----

const ARENA_BYTES: usize = 64 * 1024;

struct BumpAllocator {
    arena: UnsafeCell<[u8; ARENA_BYTES]>,
    offset: UnsafeCell<usize>,
}

// SAFETY: contracts are single-threaded (Wasm has no threads here), so the
// interior mutability is never accessed concurrently.
unsafe impl Sync for BumpAllocator {}

unsafe impl GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let offset = &mut *self.offset.get();
        let base = self.arena.get() as *mut u8;
        let aligned = (*offset + layout.align() - 1) & !(layout.align() - 1);
        let end = aligned.saturating_add(layout.size());
        if end > ARENA_BYTES {
            return core::ptr::null_mut();
        }
        *offset = end;
        base.add(aligned)
    }
    // Single-shot execution: memory is reclaimed when the instance is dropped.
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[global_allocator]
static ALLOCATOR: BumpAllocator =
    BumpAllocator { arena: UnsafeCell::new([0u8; ARENA_BYTES]), offset: UnsafeCell::new(0) };

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}
