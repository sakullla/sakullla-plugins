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
    // StateGet/StatePut is not an atomic generation-local mutation contract,
    // and the public Host exposes no monotonic time. Never emulate either.
    AbiStatus::IncompatibleAbi as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn nre_policy_evaluate(pointer: u32, length: u32) -> u64 {
    if pointer == u32::MAX {
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
    // SAFETY: OUTPUT_ACTIVE grants exclusive guest access until Host free.
    let output = unsafe { &mut *OUTPUT.0.get() };
    match encode_evaluate_error(
        output,
        RuntimeErrorCode::IncompatibleAbi,
        "required monotonic-clock and atomic-state capabilities unavailable",
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
    // SAFETY: alloc established the bounded range and guest only reads it.
    Ok(unsafe { core::slice::from_raw_parts(INPUT.0.get().cast::<u8>(), length as usize) })
}

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
            let _ = host.emit_event("rate-limit.anchor", b"");
        }
        _ => {
            let _ = host.add_metric("rate_limit_anchor", 0);
        }
    }
}
