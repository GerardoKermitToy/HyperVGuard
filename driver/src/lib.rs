#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(debug_assertions)]
compile_error!("Build the kernel driver with --release only.");
#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
compile_error!("The driver supports Windows x64 only.");

extern crate alloc;

use alloc::vec::Vec;
use core::{
    alloc::{GlobalAlloc, Layout},
    cell::UnsafeCell,
    ffi::c_void,
    panic::PanicInfo,
};
use hyperv_policy::{
    cache::{CacheAllocator, CacheWork},
    engine::{Action, Engine, Finish, Key, Submission, allocate_record},
    packet::{self, NdisPath, Packet, SNAPSHOT},
};
use hyperv_protocol::{self as wire, Command};

type Handle = *mut c_void;
const SUCCESS: i32 = 0;
const INVALID_PARAMETER: i32 = 0xc000000du32 as i32;
const NOT_SUPPORTED: i32 = 0xc00000bbu32 as i32;

#[unsafe(no_mangle)]
pub static HV_API_VERSION: [u8; 4] = wire::VERSION;

unsafe extern "C" {
    fn hv_initialize(driver: Handle, registry: Handle) -> i32;
    fn hv_lock() -> usize;
    fn hv_unlock(irql: usize);
    fn hv_read_state(ready: u32, online: u32);
    fn hv_now() -> u64;
    fn hv_allocate(size: usize) -> *mut u8;
    fn hv_free(data: *mut u8, size: usize);
    fn hv_cache_allocate(size: usize) -> *mut u8;
    fn hv_cache_free(data: *mut u8, size: usize);
    fn hv_finish(token: usize, finish: u32);
    fn hv_first_nb(token: usize) -> Handle;
    fn hv_next_nb(nb: Handle) -> Handle;
    fn hv_snapshot(
        nb: Handle,
        token: usize,
        out: *mut u8,
        cap: u32,
        copied: *mut u32,
        trusted: *mut u32,
        frame_len: *mut u32,
        offload: *mut u32,
    ) -> u32;
    fn hv_bugcheck() -> !;
}
struct NonPagedAllocator;
// SAFETY: the shim returns nonpaged pool aligned to at least 16 bytes and uses
// atomic accounting to bound all live allocations, including unlocked captures.
unsafe impl GlobalAlloc for NonPagedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.align() > 16 {
            return core::ptr::null_mut();
        }
        unsafe { hv_allocate(layout.size()) }
    }
    unsafe fn dealloc(&self, data: *mut u8, layout: Layout) {
        unsafe { hv_free(data, layout.size()) }
    }
}
#[global_allocator]
static ALLOCATOR: NonPagedAllocator = NonPagedAllocator;

struct State(UnsafeCell<Engine>);
// The C shim initializes the spin lock before ANY callback or control device is
// published. Every engine access is under it; no references escape with_state.
unsafe impl Sync for State {}
unsafe fn cache_allocate(size: usize) -> *mut u8 {
    unsafe { hv_cache_allocate(size) }
}
unsafe fn cache_free(data: *mut u8, size: usize) {
    unsafe { hv_cache_free(data, size) }
}
// SAFETY: matching fallible, nonpaged pool functions; buffers are freed unlocked.
const CACHE_ALLOCATOR: CacheAllocator = unsafe { CacheAllocator::new(cache_allocate, cache_free) };
static STATE: State = State(UnsafeCell::new(Engine::with_cache_allocator(
    CACHE_ALLOCATOR,
)));
fn with_state<R>(f: impl FnOnce(&mut Engine) -> R) -> R {
    // SAFETY: no recursion into this lock; no NDIS forwarding/completion while held.
    unsafe {
        let irql = hv_lock();
        let engine = &mut *STATE.0.get();
        let result = f(engine);
        // Publish the level while still locked: a new read cannot miss enqueue,
        // partial-read, timeout, or disconnect changes. This only schedules work.
        hv_read_state(engine.has_events() as u32, engine.is_online() as u32);
        hv_unlock(irql);
        result
    }
}
fn finish(a: Action) {
    // SAFETY: claiming a pending entry transfers its one owned NBL token. The C
    // shim retains the filter module until its eventual completion/return.
    unsafe {
        hv_finish(
            a.token,
            match a.finish {
                Finish::Allow => 0,
                Finish::Drop => 1,
                Finish::Cancel => 2,
            },
        )
    }
}
// Old per-interface table pairs move out one at a time, keeping the kernel
// stack fixed-size. No cache pool allocation/free occurs under PolicyLock.
fn reclaim_caches() {
    for _ in 0..hyperv_policy::engine::MAX_ADAPTERS {
        let Some(retired) = with_state(|e| e.take_retired_caches()) else {
            break;
        };
        drop(retired);
    }
}
fn drain() {
    loop {
        let action = with_state(|e| e.take_due(unsafe { hv_now() }));
        if let Some(action) = action {
            finish(action)
        } else {
            break;
        }
    }
}
/// # Safety
/// Only the kernel loader may call this with valid DRIVER_OBJECT/UNICODE_STRING.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DriverEntry(driver: Handle, registry: Handle) -> i32 {
    // SAFETY: opaque WDK-owned objects, validated and used by the ABI shim only.
    unsafe { hv_initialize(driver, registry) }
}
#[unsafe(no_mangle)]
pub extern "C" fn HvConfigure(timeout: u32, cache_ttl: u32, fail_closed: u32) {
    with_state(|e| e.configure(timeout, cache_ttl, fail_closed != 0));
}
#[unsafe(no_mangle)]
pub extern "C" fn HvAttach(id: u64, interface_index: u32) -> u32 {
    let result = with_state(|e| e.attach(id, interface_index) as u32);
    reclaim_caches();
    result
}
#[unsafe(no_mangle)]
pub extern "C" fn HvRestart(id: u64) -> u32 {
    with_state(|e| e.restart(id) as u32)
}
#[unsafe(no_mangle)]
pub extern "C" fn HvInvalidate(id: u64, pause: u32) {
    with_state(|e| e.invalidate(id, pause != 0));
    reclaim_caches();
}
#[unsafe(no_mangle)]
pub extern "C" fn HvDetach(id: u64) {
    with_state(|e| e.detach(id));
    reclaim_caches();
    drain();
}
#[unsafe(no_mangle)]
pub extern "C" fn HvDrain() {
    drain();
}
#[unsafe(no_mangle)]
pub extern "C" fn HvTick() {
    reclaim_caches();
    let mut work = CacheWork::empty();
    with_state(|e| e.clean_with_work(unsafe { hv_now() }, &mut work));
    drop(work);
    drain();
}
#[unsafe(no_mangle)]
pub extern "C" fn HvConnect() {
    with_state(|e| e.connect());
    reclaim_caches();
}
#[unsafe(no_mangle)]
pub extern "C" fn HvDisconnect() {
    with_state(|e| e.disconnect());
    reclaim_caches();
    drain();
}
#[unsafe(no_mangle)]
pub extern "C" fn HvCancel(id: u64, cancel: usize) {
    loop {
        let a = with_state(|e| e.cancel(id, cancel));
        if let Some(a) = a {
            finish(a)
        } else {
            break;
        }
    }
}

// The retained token keeps the first NB stable. Copy Ethernet+IP directly into
// the record allocation; submit() overwrites Ethernet with the small wire prefix.
// No packet-sized local arrays or NDIS buffer accesses under the policy lock.
fn capture_packet(nb: Handle, token: usize, packet: &Packet) -> Result<Option<Vec<u8>>, ()> {
    let layout = packet.capture_layout().ok_or(())?;
    let Some(mut data) = allocate_record(layout.record_len) else {
        return Ok(None);
    };
    let (mut copied, mut trusted, mut frame_len, mut offload) = (0, 0, 0, 0);
    // SAFETY: the C caller owns this NB until HvClassify returns or publishes its
    // pending token. The destination is an exclusively owned nonpaged allocation.
    let ok = unsafe {
        hv_snapshot(
            nb,
            token,
            data[layout.frame_start..].as_mut_ptr(),
            layout.frame_len as u32,
            &mut copied,
            &mut trusted,
            &mut frame_len,
            &mut offload,
        )
    };
    if ok == 0 || copied as usize != layout.frame_len || trusted < copied || frame_len < copied {
        return Err(());
    }
    Ok(Some(data))
}

// Return -1 if the engine now owns token; otherwise the caller finishes it after
// releasing the per-module classification lock. No NDIS calls occur under the
// global policy lock. Adapter/epoch identities never leave the driver.
#[unsafe(no_mangle)]
pub extern "C" fn HvClassify(
    token: usize,
    id: u64,
    epoch: u64,
    path: u32,
    vlan: u32,
    cancel: usize,
) -> i32 {
    let Some(path) = NdisPath::decode(path) else {
        with_state(|e| e.malformed());
        return 1;
    };
    let mut first: Option<Packet> = None;
    let mut saw_non_ip = false;
    let mut count = 0usize;
    let mut nb = unsafe { hv_first_nb(token) };
    while !nb.is_null() {
        count += 1;
        if count > 64 {
            with_state(|e| e.malformed());
            return 1;
        }
        let mut bytes = [0u8; SNAPSHOT];
        let (mut copied, mut trusted, mut frame_len, mut offload) = (0, 0, 0, 0);
        let ok = unsafe {
            hv_snapshot(
                nb,
                token,
                bytes.as_mut_ptr(),
                SNAPSHOT as u32,
                &mut copied,
                &mut trusted,
                &mut frame_len,
                &mut offload,
            )
        };
        if ok == 0 || copied as usize > SNAPSHOT {
            with_state(|e| e.malformed());
            return 1;
        }
        let parsed = packet::parse(
            &bytes[..copied as usize],
            trusted as usize,
            frame_len as usize,
            offload != 0,
        );
        match parsed {
            Ok(Some(p)) => {
                if saw_non_ip {
                    with_state(|e| e.malformed());
                    return 1;
                }
                if let Some(f) = &mut first {
                    // A single legacy request cannot describe two different flows.
                    if f.flow != p.flow {
                        with_state(|e| e.malformed());
                        return 1;
                    }
                    f.ip_len = f.ip_len.saturating_add(p.ip_len);
                    f.cacheable = false; // no permanent decision from a batch
                } else {
                    first = Some(p);
                }
            }
            Ok(None) => {
                if first.is_some() {
                    with_state(|e| e.malformed());
                    return 1;
                }
                saw_non_ip = true;
            }
            Err(packet::ParseError::TooLarge) => {
                with_state(|e| e.resource_drop());
                return 1;
            }
            Err(_) => {
                with_state(|e| e.malformed());
                return 1;
            }
        }
        nb = unsafe { hv_next_nb(nb) };
    }
    if count == 0 {
        with_state(|e| e.malformed());
        return 1;
    }
    let Some(mut packet) = first else {
        with_state(|e| e.non_ip());
        return 0;
    };
    packet.orient(path);
    let key = Key {
        adapter: id,
        epoch,
        path,
        vlan,
        flow: packet.flow,
    };
    let wants_event = match with_state(|e| e.preflight(&key, &packet, token, unsafe { hv_now() })) {
        Ok(wants_event) => wants_event,
        Err(action) => {
            return match action.finish {
                Finish::Allow => 0,
                Finish::Drop => 1,
                Finish::Cancel => 2,
            };
        }
    };
    let record = if wants_event {
        match capture_packet(unsafe { hv_first_nb(token) }, token, &packet) {
            Ok(record) => record,
            Err(()) => {
                with_state(|e| e.malformed());
                return 1;
            }
        }
    } else {
        None
    };
    match with_state(|e| e.submit(key, packet, token, cancel, unsafe { hv_now() }, record)) {
        Submission::Pending(_) => -1,
        Submission::Finish(a) => match a.finish {
            Finish::Allow => 0,
            Finish::Drop => 1,
            Finish::Cancel => 2,
        },
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn HvResourceDrop() {
    with_state(|e| e.resource_drop());
}

// Synchronous buffered device requests are nonblocking. The user-mode reader
// waits briefly on empty reads, so no cancel-unsafe IRPs or kernel waiters exist.
/// # Safety
/// `out` is an exclusively writable nonpaged system buffer of at least `len`
/// bytes, valid for the entire call, supplied by the buffered IRP shim.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn HvRead(out: *mut u8, len: u32) -> u32 {
    if out.is_null() || len == 0 {
        return 0;
    }
    // SAFETY: the shim provides the system buffer and its exact validated size.
    let out = unsafe { core::slice::from_raw_parts_mut(out, len as usize) };
    with_state(|e| e.read(out)) as u32
}
/// # Safety
/// `data` is a readable nonpaged system buffer of at least `len` bytes, immutable
/// for the call and serialized with client cleanup by the C shim's I/O mutex.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn HvWrite(data: *const u8, len: u32) -> i32 {
    if data.is_null() || len == 0 || len > 65536 {
        return INVALID_PARAMETER;
    }
    let bytes = unsafe { core::slice::from_raw_parts(data, len as usize) };
    if let Err(error) = wire::validate_commands(bytes) {
        return match error {
            wire::Error::Unsupported => NOT_SUPPORTED,
            _ => INVALID_PARAMETER,
        };
    }
    let mut rest = bytes;
    while !rest.is_empty() {
        let Ok((command, next)) = wire::next_command(rest) else {
            return INVALID_PARAMETER;
        };
        match command {
            Command::Shutdown => {
                with_state(|e| e.disconnect());
                reclaim_caches();
                drain();
            }
            Command::Verdict { id, verdict } => {
                // Expiry and topology changes may win the race. A stale ID is a
                // harmless no-op (never a cache write), as on asynchronous kext I/O.
                let plan = with_state(|e| e.cache_plan(id, verdict, unsafe { hv_now() }));
                let mut work = CacheWork::prepare(plan);
                let action = with_state(|e| {
                    e.verdict_with_work(id, verdict, unsafe { hv_now() }, &mut work)
                        .ok()
                });
                drop(work);
                if let Some(a) = action {
                    finish(a);
                } else {
                    drain();
                }
            }
            Command::ClearCache => {
                with_state(|e| e.clear_cache());
                reclaim_caches();
            }
            Command::GetLogs => {} // Log records are already queued.
            Command::GetBandwidth => with_state(|e| e.bandwidth()),
            Command::MemoryStats => with_state(|e| e.memory_stats()),
            Command::CleanEnded => {
                reclaim_caches();
                let mut work = CacheWork::empty();
                with_state(|e| e.clean_with_work(unsafe { hv_now() }, &mut work));
                drop(work);
            }
        }
        rest = next;
    }
    SUCCESS
}
#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    unsafe { hv_bugcheck() }
}
// MSVC's kernel CRT archive supplies the actual memory primitives.
#[unsafe(no_mangle)]
pub static _fltused: i32 = 0;
