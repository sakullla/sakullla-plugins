#![cfg_attr(target_arch = "wasm32", no_std)]
#![forbid(unsafe_op_in_unsafe_fn)]

mod config_json;
mod engine;

pub use config_json::{ConfigDecodeError, decode_config};
pub use engine::{
    BodyWindow, ConfigError, CustomRule, DecisionReason, Evaluation, Exclusion, NormalizedRequest,
    PreparedConfig, Target, TrustedSource, WafConfig, WafEngine, WafMode, prepare_config,
};

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use core::cell::UnsafeCell;
    use core::slice;

    use nre_policy_guest::{
        ABI_MAJOR_VERSION, AbiStatus, EvaluateRequest, HostClient, HostLimits, InitRequest,
        PolicyAction, RuntimeErrorCode, WasmHost, WireLimits, encode_evaluate_error,
        encode_evaluate_success, pack_policy_buffer,
    };

    use crate::{
        BodyWindow, NormalizedRequest, PreparedConfig, TrustedSource, WafEngine, WafMode,
        decode_config,
    };

    const ARENA_BYTES: usize = 132 * 1024;
    const OUTPUT_BYTES: usize = 4096;
    const FIELD_BYTES: usize = 4096;
    const BODY_WINDOW_BYTES: usize = 4088;

    struct Shared<T>(UnsafeCell<T>);

    // A policy instance is entered serially by its host. Keeping the unsafe
    // boundary here makes that ABI invariant explicit and auditable.
    unsafe impl<T> Sync for Shared<T> {}

    struct Runtime {
        arena: [u8; ARENA_BYTES + OUTPUT_BYTES],
        cursor: usize,
        config: PreparedConfig,
        initialized: bool,
    }

    static RUNTIME: Shared<Runtime> = Shared(UnsafeCell::new(Runtime {
        arena: [0; ARENA_BYTES + OUTPUT_BYTES],
        cursor: 0,
        config: PreparedConfig::managed_only(WafMode::Deny),
        initialized: false,
    }));

    #[derive(Clone, Copy)]
    struct Field<const N: usize> {
        bytes: [u8; N],
        len: usize,
        found: bool,
    }

    impl<const N: usize> Field<N> {
        const EMPTY: Self = Self {
            bytes: [0; N],
            len: 0,
            found: false,
        };

        fn set(&mut self, value: &[u8], found: bool) -> Result<(), AbiStatus> {
            if value.len() > N {
                return Err(AbiStatus::ResourceExhausted);
            }
            // SAFETY: length was bounded above and source/destination do not overlap.
            unsafe {
                core::ptr::copy_nonoverlapping(value.as_ptr(), self.bytes.as_mut_ptr(), value.len())
            };
            self.len = value.len();
            self.found = found;
            Ok(())
        }

        fn as_slice(&self) -> &[u8] {
            self.bytes.get(..self.len).unwrap_or(&[])
        }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn nre_policy_version() -> u32 {
        ABI_MAJOR_VERSION
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn nre_policy_alloc(length: u32) -> u32 {
        let length = length as usize;
        if length == 0 || length > ARENA_BYTES {
            return 0;
        }
        // SAFETY: the host serializes calls into one policy instance.
        let runtime = unsafe { &mut *RUNTIME.0.get() };
        runtime.cursor = length;
        let Some(input) = runtime.arena.get_mut(..length) else {
            return 0;
        };
        input.fill(0);
        runtime.arena.as_mut_ptr() as u32
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn nre_policy_free(_pointer: u32, _length: u32) {
        // The fixed arena is instance-owned. The next allocation reclaims it.
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn nre_policy_init(pointer: u32, length: u32) -> u32 {
        let input = match guest_input(pointer, length) {
            Some(input) => input,
            None => return AbiStatus::InvalidArgument as u32,
        };
        let request = match InitRequest::decode(input, WireLimits::POLICY_INPUT) {
            Ok(request) => request,
            Err(error) => return error.status as u32,
        };
        for required in [
            "policy.read-normalized-http",
            "policy.read-body-window",
            "policy.emit-event",
            "policy.add-metric",
        ] {
            match request.granted_scopes.contains(required) {
                Ok(true) => {}
                Ok(false) => return AbiStatus::PermissionDenied as u32,
                Err(error) => return error.status as u32,
            }
        }
        let config = match decode_config(request.config) {
            Ok(config) => config,
            Err(_) => return AbiStatus::InvalidArgument as u32,
        };
        // SAFETY: the host serializes calls into one policy instance.
        let runtime = unsafe { &mut *RUNTIME.0.get() };
        runtime.config = config;
        runtime.initialized = true;
        AbiStatus::Ok as u32
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn nre_policy_evaluate(pointer: u32, length: u32) -> u64 {
        let input = match guest_input(pointer, length) {
            Some(input) => input,
            None => return error_response(RuntimeErrorCode::InvalidArgument, "invalid input"),
        };
        if EvaluateRequest::decode(input, WireLimits::POLICY_INPUT).is_err() {
            return error_response(RuntimeErrorCode::InvalidArgument, "invalid request");
        }
        // SAFETY: the host serializes calls into one policy instance.
        let runtime = unsafe { &mut *RUNTIME.0.get() };
        if !runtime.initialized {
            return error_response(RuntimeErrorCode::Unavailable, "policy not initialized");
        }

        match evaluate_with_host(&runtime.config) {
            Ok((action, event, event_len)) => {
                let Some(event) = event.get(..event_len) else {
                    return error_response(RuntimeErrorCode::Internal, "invalid event");
                };
                let host_result = emit_observability(action, event);
                if let Err(status) = host_result {
                    return error_response(runtime_error(status), "host operation failed");
                }
                success_response(action, event)
            }
            Err(status) => error_response(runtime_error(status), "host read failed"),
        }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn nre_policy_reset() -> u32 {
        // SAFETY: the host serializes calls into one policy instance.
        let runtime = unsafe { &mut *RUNTIME.0.get() };
        runtime.cursor = 0;
        runtime.config = PreparedConfig::managed_only(WafMode::Deny);
        runtime.initialized = false;
        AbiStatus::Ok as u32
    }

    fn evaluate_with_host(
        config: &PreparedConfig,
    ) -> Result<(PolicyAction, [u8; 256], usize), AbiStatus> {
        let mut host: HostClient<WasmHost, 512, FIELD_BYTES> =
            HostClient::new(WasmHost, HostLimits::new(16, 256)).map_err(|error| error.status)?;
        let mut site = Field::<96>::EMPTY;
        let mut method = Field::<16>::EMPTY;
        let mut path = Field::<1024>::EMPTY;
        let mut query = Field::<1024>::EMPTY;
        let mut headers = Field::<2048>::EMPTY;
        let mut source = Field::<64>::EMPTY;
        let mut authenticated = Field::<8>::EMPTY;
        let mut complete = Field::<8>::EMPTY;
        read_field(&mut host, "site", &mut site)?;
        read_field(&mut host, "method", &mut method)?;
        read_field(&mut host, "path", &mut path)?;
        read_field(&mut host, "query", &mut query)?;
        read_field(&mut host, "headers", &mut headers)?;
        read_field(&mut host, "trusted_source", &mut source)?;
        read_field(
            &mut host,
            "trusted_source_authenticated",
            &mut authenticated,
        )?;
        read_field(&mut host, "body_window_complete", &mut complete)?;
        let mut body = Field::<BODY_WINDOW_BYTES>::EMPTY;
        let response = host
            .read_body_window(0, BODY_WINDOW_BYTES as u32)
            .map_err(|error| error.status)?;
        body.set(response.value, response.found)?;

        // Generation-owned state is touched only through the canonical host
        // surface. It does not contain request or source material.
        let state = host.state_get("waf.active").map_err(|error| error.status)?;
        if !state.found {
            host.state_put("waf.active", b"1")
                .map_err(|error| error.status)?;
        }

        let site_text = core::str::from_utf8(site.as_slice()).unwrap_or("unknown");
        let body_window = if !body.found {
            BodyWindow::Unavailable
        } else if complete.as_slice() == b"true" {
            BodyWindow::Complete(body.as_slice())
        } else {
            BodyWindow::Truncated(body.as_slice())
        };
        let evaluation = WafEngine::new(config).evaluate(NormalizedRequest {
            site: site_text,
            method: method.as_slice(),
            path: path.as_slice(),
            query: query.as_slice(),
            headers: headers.as_slice(),
            trusted_source: TrustedSource {
                authenticated: authenticated.as_slice() == b"true" && source.found,
                address: source.as_slice(),
            },
            body: body_window,
        });
        let mut event = [0; 256];
        let event_len = evaluation
            .write_event(site_text, &mut event)
            .ok_or(AbiStatus::ResourceExhausted)?;
        Ok((evaluation.action, event, event_len))
    }

    fn read_field<const N: usize>(
        host: &mut HostClient<WasmHost, 512, FIELD_BYTES>,
        name: &str,
        output: &mut Field<N>,
    ) -> Result<(), AbiStatus> {
        let response = host.read_field(name).map_err(|error| error.status)?;
        output.set(response.value, response.found)
    }

    fn emit_observability(action: PolicyAction, event: &[u8]) -> Result<(), AbiStatus> {
        let mut host: HostClient<WasmHost, 512, 64> =
            HostClient::new(WasmHost, HostLimits::new(2, 64)).map_err(|error| error.status)?;
        if action != PolicyAction::Allow {
            host.emit_event("waf.decision", event)
                .map_err(|error| error.status)?;
        }
        host.add_metric("waf.evaluations", 1)
            .map_err(|error| error.status)
    }

    fn success_response(action: PolicyAction, payload: &[u8]) -> u64 {
        // SAFETY: the host serializes calls into one policy instance.
        let runtime = unsafe { &mut *RUNTIME.0.get() };
        let start = runtime.cursor.min(ARENA_BYTES);
        let Some(output) = runtime.arena.get_mut(start..start + OUTPUT_BYTES) else {
            return 0;
        };
        match encode_evaluate_success(output, action, payload) {
            Ok(encoded) => pack_policy_buffer(encoded.as_ptr() as u32, encoded.len() as u32),
            Err(_) => 0,
        }
    }

    fn error_response(code: RuntimeErrorCode, message: &str) -> u64 {
        // SAFETY: the host serializes calls into one policy instance.
        let runtime = unsafe { &mut *RUNTIME.0.get() };
        let start = runtime.cursor.min(ARENA_BYTES);
        let Some(output) = runtime.arena.get_mut(start..start + OUTPUT_BYTES) else {
            return 0;
        };
        match encode_evaluate_error(output, code, message, false) {
            Ok(encoded) => pack_policy_buffer(encoded.as_ptr() as u32, encoded.len() as u32),
            Err(_) => 0,
        }
    }

    fn guest_input(pointer: u32, length: u32) -> Option<&'static [u8]> {
        let length = length as usize;
        if pointer == 0 || length == 0 || length > ARENA_BYTES {
            return None;
        }
        // SAFETY: the host supplies the exact guest allocation returned by
        // nre_policy_alloc and the range was bounded above.
        Some(unsafe { slice::from_raw_parts(pointer as *const u8, length) })
    }

    fn runtime_error(status: AbiStatus) -> RuntimeErrorCode {
        match status {
            AbiStatus::InvalidArgument => RuntimeErrorCode::InvalidArgument,
            AbiStatus::PermissionDenied => RuntimeErrorCode::PermissionDenied,
            AbiStatus::ResourceExhausted => RuntimeErrorCode::ResourceExhausted,
            AbiStatus::DeadlineExceeded => RuntimeErrorCode::DeadlineExceeded,
            AbiStatus::Unavailable => RuntimeErrorCode::Unavailable,
            AbiStatus::IncompatibleAbi => RuntimeErrorCode::IncompatibleAbi,
            AbiStatus::Internal | AbiStatus::Ok => RuntimeErrorCode::Internal,
        }
    }
}
