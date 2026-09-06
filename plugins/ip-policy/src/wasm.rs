use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, Ordering};

use nre_policy_guest::{
    ABI_MAJOR_VERSION, AbiStatus, EvaluateRequest, HostClient, HostLimits, InitRequest,
    RuntimeErrorCode, WasmHost, WireLimits, encode_evaluate_error, encode_evaluate_success,
    pack_policy_buffer,
};

use crate::runtime::{init_lifecycle_status, reset_lifecycle_status, valid_input_allocation};
use crate::{EvaluationError, RuntimeState, emit_failure};

const INPUT_BYTES: usize = 128 << 10;
const OUTPUT_BYTES: usize = 4 << 10;

struct Shared<T>(UnsafeCell<T>);

unsafe impl<T> Sync for Shared<T> {}

static INPUT: Shared<[u8; INPUT_BYTES + 1]> = Shared(UnsafeCell::new([0; INPUT_BYTES + 1]));
static OUTPUT: Shared<[u8; OUTPUT_BYTES]> = Shared(UnsafeCell::new([0; OUTPUT_BYTES]));
static STATE: Shared<MaybeUninit<RuntimeState>> = Shared(UnsafeCell::new(MaybeUninit::uninit()));
static INPUT_ACTIVE: AtomicBool = AtomicBool::new(false);
static OUTPUT_ACTIVE: AtomicBool = AtomicBool::new(false);
static INITIALIZED: AtomicBool = AtomicBool::new(false);

#[unsafe(no_mangle)]
pub extern "C" fn nre_policy_version() -> u32 {
    ABI_MAJOR_VERSION
}

#[unsafe(no_mangle)]
pub extern "C" fn nre_policy_alloc(size: u32) -> u32 {
    if !valid_input_allocation(size, INPUT_BYTES)
        || INPUT_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        return 0;
    }
    input_pointer()
}

#[unsafe(no_mangle)]
pub extern "C" fn nre_policy_free(pointer: u32, length: u32) {
    if pointer == input_pointer() && length as usize <= INPUT_BYTES {
        INPUT_ACTIVE.store(false, Ordering::Release);
    } else if pointer == OUTPUT.0.get().cast::<u8>() as u32 && length as usize <= OUTPUT_BYTES {
        OUTPUT_ACTIVE.store(false, Ordering::Release);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn nre_policy_init(pointer: u32, length: u32) -> u32 {
    let lifecycle = init_lifecycle_status(INITIALIZED.load(Ordering::Acquire));
    if lifecycle != AbiStatus::Ok {
        return lifecycle as u32;
    }
    let Ok(frame) = input_frame(pointer, length) else {
        return AbiStatus::InvalidArgument as u32;
    };
    let Ok(request) = InitRequest::decode(frame, WireLimits::POLICY_INPUT) else {
        return AbiStatus::InvalidArgument as u32;
    };
    match RuntimeState::initialize(request, WasmHost) {
        Ok(state) => {
            // SAFETY: a policy instance is single-threaded. Initialization owns
            // STATE until the release-store publishes the completed value.
            unsafe { (*STATE.0.get()).write(state) };
            INITIALIZED.store(true, Ordering::Release);
            AbiStatus::Ok as u32
        }
        Err(error) => error_status(error) as u32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn nre_policy_evaluate(pointer: u32, length: u32) -> u64 {
    if pointer == u32::MAX {
        retain_required_imports(length);
        return 0;
    }
    if !INITIALIZED.load(Ordering::Acquire) {
        return encode_error(RuntimeErrorCode::Unavailable, "policy-not-initialized");
    }
    let frame = match input_frame(pointer, length) {
        Ok(frame) => frame,
        Err(_) => return encode_error(RuntimeErrorCode::InvalidArgument, "invalid-input-frame"),
    };
    let request = match EvaluateRequest::decode(frame, WireLimits::POLICY_INPUT) {
        Ok(request)
            if matches!(request.extension_point, "http.request" | "l4.accept")
                && !request.request_id.is_empty() =>
        {
            request
        }
        _ => {
            return encode_error(
                RuntimeErrorCode::InvalidArgument,
                "invalid-evaluate-request",
            );
        }
    };
    // SAFETY: the acquire-load observes a completed initialization. Runtime
    // state is immutable during evaluate.
    let state = unsafe { (*STATE.0.get()).assume_init_ref() };
    match state.evaluate(request.payload, WasmHost) {
        Ok(result) => encode_success(result.action),
        Err(error) => {
            emit_failure(error, WasmHost);
            encode_error(error.code, error_message(error))
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn nre_policy_reset() -> u32 {
    let lifecycle = reset_lifecycle_status(
        INPUT_ACTIVE.load(Ordering::Acquire),
        OUTPUT_ACTIVE.load(Ordering::Acquire),
    );
    if lifecycle != AbiStatus::Ok {
        return lifecycle as u32;
    }
    // Reset is a per-request pool boundary. Immutable generation state remains
    // valid until the Host closes this WASM instance.
    AbiStatus::Ok as u32
}

fn encode_success(action: nre_policy_guest::PolicyAction) -> u64 {
    let Some(output) = output_buffer() else {
        return 0;
    };
    match encode_evaluate_success(output, action, &[]) {
        Ok(frame) => pack_policy_buffer(OUTPUT.0.get().cast::<u8>() as u32, frame.len() as u32),
        Err(_) => release_failed_output(),
    }
}

fn encode_error(code: RuntimeErrorCode, message: &'static str) -> u64 {
    let Some(output) = output_buffer() else {
        return 0;
    };
    match encode_evaluate_error(output, code, message, false) {
        Ok(frame) => pack_policy_buffer(OUTPUT.0.get().cast::<u8>() as u32, frame.len() as u32),
        Err(_) => release_failed_output(),
    }
}

fn output_buffer() -> Option<&'static mut [u8; OUTPUT_BYTES]> {
    if OUTPUT_ACTIVE
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return None;
    }
    // SAFETY: OUTPUT_ACTIVE grants exclusive access until Host free.
    Some(unsafe { &mut *OUTPUT.0.get() })
}

fn release_failed_output() -> u64 {
    OUTPUT_ACTIVE.store(false, Ordering::Release);
    0
}

fn input_frame(pointer: u32, length: u32) -> Result<&'static [u8], ()> {
    if !INPUT_ACTIVE.load(Ordering::Acquire)
        || pointer != input_pointer()
        || length == 0
        || length as usize > INPUT_BYTES
    {
        return Err(());
    }
    // SAFETY: alloc established this bounded range and guest only reads it.
    Ok(unsafe { core::slice::from_raw_parts(input_pointer() as *const u8, length as usize) })
}

fn input_pointer() -> u32 {
    // Byte zero is deliberately reserved because the ABI uses pointer zero as
    // allocation failure even when rust-lld places this static at memory base.
    INPUT.0.get().cast::<u8>() as u32 + 1
}

fn error_status(error: RuntimeErrorCode) -> AbiStatus {
    match error {
        RuntimeErrorCode::InvalidArgument => AbiStatus::InvalidArgument,
        RuntimeErrorCode::PermissionDenied => AbiStatus::PermissionDenied,
        RuntimeErrorCode::ResourceExhausted => AbiStatus::ResourceExhausted,
        RuntimeErrorCode::DeadlineExceeded => AbiStatus::DeadlineExceeded,
        RuntimeErrorCode::Unavailable => AbiStatus::Unavailable,
        RuntimeErrorCode::IncompatibleAbi => AbiStatus::IncompatibleAbi,
        RuntimeErrorCode::Internal | RuntimeErrorCode::Unspecified => AbiStatus::Internal,
    }
}

fn error_message(error: EvaluationError) -> &'static str {
    use nre_policy_guest::SecurityEventReason as Reason;
    match error.event.reason {
        Reason::SourceUnauthenticated => "source-unauthenticated",
        Reason::DatasetUnavailable => "dataset-unavailable",
        Reason::ClassificationMissing => "classification-missing",
        Reason::BudgetExceeded => "budget-exceeded",
        Reason::DataInvalid => "data-invalid",
        Reason::CoverageUnknown => "coverage-unknown",
        _ => "policy-check-failed",
    }
}

fn retain_required_imports(operation: u32) {
    let Ok(mut host) = HostClient::<_, 256, 256>::new(WasmHost, HostLimits::new(2, 64)) else {
        return;
    };
    match operation % 6 {
        0 => {
            let _ = host.read_field("normalized.source");
        }
        1 => {
            let _ = host.read_normalized_http();
        }
        2 => {
            let _ = host.read_body_window(0, 1);
        }
        3 => {
            let _ = host.state_get("generation");
        }
        4 => {
            let _ = host.state_put("generation", b"anchor");
        }
        _ => {
            let _ = host.add_metric("ip_policy_anchor", 0);
        }
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
