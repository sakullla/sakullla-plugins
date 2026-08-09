use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

use nre_policy_guest::{
    ABI_MAJOR_VERSION, AbiStatus, HostClient, HostLimits, InitRequest, RuntimeErrorCode, WasmHost,
    WireLimits, encode_evaluate_error, pack_policy_buffer,
};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

const INPUT_BYTES: usize = 128 << 10;
const OUTPUT_BYTES: usize = 4 << 10;

struct SharedBuffer<const N: usize>(UnsafeCell<[u8; N]>);

// WebAssembly policy instances are single-threaded by contract. Atomic flags
// still make ownership transitions explicit to the Rust aliasing model.
unsafe impl<const N: usize> Sync for SharedBuffer<N> {}

static INPUT: SharedBuffer<INPUT_BYTES> = SharedBuffer(UnsafeCell::new([0; INPUT_BYTES]));
static OUTPUT: SharedBuffer<OUTPUT_BYTES> = SharedBuffer(UnsafeCell::new([0; OUTPUT_BYTES]));
static INPUT_ACTIVE: AtomicBool = AtomicBool::new(false);
static OUTPUT_ACTIVE: AtomicBool = AtomicBool::new(false);

#[unsafe(no_mangle)]
pub extern "C" fn nre_policy_version() -> u32 {
    ABI_MAJOR_VERSION
}

#[unsafe(no_mangle)]
pub extern "C" fn nre_policy_alloc(size: u32) -> u32 {
    if size == 0
        || size as usize > INPUT_BYTES
        || INPUT_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        return 0;
    }
    INPUT.0.get().cast::<u8>() as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn nre_policy_free(pointer: u32, length: u32) {
    if pointer == INPUT.0.get().cast::<u8>() as u32 && length as usize <= INPUT_BYTES {
        INPUT_ACTIVE.store(false, Ordering::Release);
    } else if pointer == OUTPUT.0.get().cast::<u8>() as u32 && length as usize <= OUTPUT_BYTES {
        OUTPUT_ACTIVE.store(false, Ordering::Release);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn nre_policy_init(pointer: u32, length: u32) -> u32 {
    let Ok(frame) = input_frame(pointer, length) else {
        return AbiStatus::InvalidArgument as u32;
    };
    let Ok(request) = InitRequest::decode(frame, WireLimits::POLICY_INPUT) else {
        return AbiStatus::InvalidArgument as u32;
    };
    if request.config.is_empty() || request.generation.is_empty() {
        return AbiStatus::InvalidArgument as u32;
    }
    // The pinned public SDK cannot authenticate whether ReadField source data
    // came from socket, PROXY protocol, or Relay metadata. Do not invent a
    // private field name: admission and runtime initialization both fail closed.
    AbiStatus::IncompatibleAbi as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn nre_policy_evaluate(pointer: u32, length: u32) -> u64 {
    if pointer == u32::MAX {
        // This cannot name a valid linear-memory range. Keeping the branch in a
        // canonical export retains the complete required Host import surface
        // without adding a private guest export or a callable success path.
        retain_canonical_imports(length);
        return 0;
    }
    if input_frame(pointer, length).is_err()
        || OUTPUT_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        return 0;
    }
    // SAFETY: OUTPUT_ACTIVE grants this call exclusive access until Host free.
    let output = unsafe { &mut *OUTPUT.0.get() };
    match encode_evaluate_error(
        output,
        RuntimeErrorCode::IncompatibleAbi,
        "required trusted-source capability unavailable",
        false,
    ) {
        Ok(frame) => pack_policy_buffer(OUTPUT.0.get().cast::<u8>() as u32, frame.len() as u32),
        Err(_) => {
            OUTPUT_ACTIVE.store(false, Ordering::Release);
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn nre_policy_reset() -> u32 {
    if INPUT_ACTIVE.load(Ordering::Acquire) || OUTPUT_ACTIVE.load(Ordering::Acquire) {
        AbiStatus::InvalidArgument as u32
    } else {
        AbiStatus::Ok as u32
    }
}

fn input_frame(pointer: u32, length: u32) -> Result<&'static [u8], ()> {
    if !INPUT_ACTIVE.load(Ordering::Acquire)
        || pointer != INPUT.0.get().cast::<u8>() as u32
        || length == 0
        || length as usize > INPUT_BYTES
    {
        return Err(());
    }
    // SAFETY: alloc established exclusive Host ownership of this bounded range;
    // guest only reads it between the Host write and matching free.
    Ok(unsafe { core::slice::from_raw_parts(INPUT.0.get().cast::<u8>(), length as usize) })
}

// A runtime argument prevents optimization from deleting any branch, proving
// the artifact imports exactly the six canonical Host functions without
// copying ABI strings here.
fn retain_canonical_imports(operation: u32) {
    let Ok(mut host) = HostClient::<_, 256, 256>::new(WasmHost, HostLimits::new(2, 64)) else {
        return;
    };
    match operation % 6 {
        0 => {
            let _ = host.read_field("normalized.source");
        }
        1 => {
            let _ = host.read_body_window(0, 1);
        }
        2 => {
            let _ = host.state_get("generation");
        }
        3 => {
            let _ = host.state_put("generation", b"anchor");
        }
        4 => {
            let _ = host.emit_event("ip-policy.anchor", b"");
        }
        _ => {
            let _ = host.add_metric("ip_policy_anchor", 0);
        }
    }
}
