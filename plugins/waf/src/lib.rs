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
        NormalizedHttpResponse, PolicyAction, RuntimeErrorCode, WasmHost, WireLimits,
        encode_evaluate_error, encode_evaluate_success, pack_policy_buffer,
    };

    use crate::{
        BodyWindow, NormalizedRequest, PreparedConfig, TrustedSource, WafEngine, WafMode,
        decode_config,
    };

    const ARENA_BYTES: usize = 132 * 1024;
    const OUTPUT_BYTES: usize = 4096;
    const FIELD_BYTES: usize = 4096;
    const BODY_WINDOW_BYTES: usize = 4088;

    type WafHost = HostClient<WasmHost, 512, FIELD_BYTES>;

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

    struct SnapshotFields {
        path: Field<1024>,
        query: Field<1024>,
        headers: Field<2048>,
        source: Field<64>,
        source_authenticated: bool,
        body_window_complete: bool,
        body_window_length: usize,
    }

    impl SnapshotFields {
        fn copy_from(snapshot: NormalizedHttpResponse<'_>) -> Result<Self, AbiStatus> {
            let mut fields = Self {
                path: Field::EMPTY,
                query: Field::EMPTY,
                headers: Field::EMPTY,
                source: Field::EMPTY,
                source_authenticated: snapshot.trusted_source_authenticated,
                body_window_complete: snapshot.body_window_complete,
                body_window_length: snapshot.body_window_length as usize,
            };
            fields.path.set(snapshot.path, true)?;
            fields.query.set(snapshot.query, true)?;
            fields.headers.set(snapshot.headers, true)?;
            fields
                .source
                .set(snapshot.trusted_source, !snapshot.trusted_source.is_empty())?;
            Ok(fields)
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
        let request = match EvaluateRequest::decode(input, WireLimits::POLICY_INPUT) {
            Ok(request) => request,
            Err(_) => return error_response(RuntimeErrorCode::InvalidArgument, "invalid request"),
        };
        // SAFETY: the host serializes calls into one policy instance.
        let runtime = unsafe { &mut *RUNTIME.0.get() };
        if !runtime.initialized {
            return error_response(RuntimeErrorCode::Unavailable, "policy not initialized");
        }

        let mut host = None;
        let snapshot = if request.normalized_http.is_empty() {
            let current = match ensure_host(&mut host) {
                Ok(host) => host,
                Err(status) => {
                    return error_response(runtime_error(status), "host unavailable");
                }
            };
            let response = match current.read_normalized_http() {
                Ok(response) => response,
                Err(error) => {
                    return error_response(runtime_error(error.status), "host read failed");
                }
            };
            match SnapshotFields::copy_from(response) {
                Ok(snapshot) => snapshot,
                Err(status) => return error_response(runtime_error(status), "host read failed"),
            }
        } else {
            let response = match NormalizedHttpResponse::decode(
                request.normalized_http,
                WireLimits::POLICY_OUTPUT,
            ) {
                Ok(response) => response,
                Err(error) => {
                    return error_response(runtime_error(error.status), "invalid snapshot");
                }
            };
            match SnapshotFields::copy_from(response) {
                Ok(snapshot) => snapshot,
                Err(status) => return error_response(runtime_error(status), "invalid snapshot"),
            }
        };
        match evaluate_snapshot(&runtime.config, &snapshot, &mut host) {
            Ok((action, event, event_len)) => {
                let Some(event) = event.get(..event_len) else {
                    return error_response(RuntimeErrorCode::Internal, "invalid event");
                };
                if action != PolicyAction::Allow {
                    let current = match ensure_host(&mut host) {
                        Ok(host) => host,
                        Err(status) => {
                            return error_response(runtime_error(status), "host unavailable");
                        }
                    };
                    if let Err(status) = emit_observability(current, action) {
                        return error_response(runtime_error(status), "host operation failed");
                    }
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
        // Clear only per-request allocation/output state. The parsed config and
        // initialized generation remain reusable across requests.
        AbiStatus::Ok as u32
    }

    fn evaluate_snapshot(
        config: &PreparedConfig,
        snapshot: &SnapshotFields,
        host: &mut Option<WafHost>,
    ) -> Result<(PolicyAction, [u8; 256], usize), AbiStatus> {
        let engine = WafEngine::new(config);
        let request = NormalizedRequest {
            path: snapshot.path.as_slice(),
            query: snapshot.query.as_slice(),
            headers: snapshot.headers.as_slice(),
            trusted_source: TrustedSource {
                authenticated: snapshot.source_authenticated && snapshot.source.found,
                address: snapshot.source.as_slice(),
            },
            body: BodyWindow::Unavailable,
        };
        let mut evaluation = engine.evaluate(request);
        if evaluation.reason == crate::DecisionReason::BodyWindowSkipped {
            let mut body = Field::<BODY_WINDOW_BYTES>::EMPTY;
            let body_window = if snapshot.body_window_length == 0 {
                if snapshot.body_window_complete {
                    BodyWindow::Complete(&[])
                } else {
                    BodyWindow::Truncated(&[])
                }
            } else {
                let requested = core::cmp::min(snapshot.body_window_length, BODY_WINDOW_BYTES);
                let response = ensure_host(host)?
                    .read_body_window(0, requested as u32)
                    .map_err(|error| error.status)?;
                body.set(response.value, response.found)?;
                if !body.found {
                    BodyWindow::Unavailable
                } else if snapshot.body_window_complete
                    && snapshot.body_window_length <= BODY_WINDOW_BYTES
                {
                    BodyWindow::Complete(body.as_slice())
                } else {
                    BodyWindow::Truncated(body.as_slice())
                }
            };
            evaluation = engine.evaluate(NormalizedRequest {
                path: snapshot.path.as_slice(),
                query: snapshot.query.as_slice(),
                headers: snapshot.headers.as_slice(),
                trusted_source: TrustedSource {
                    authenticated: snapshot.source_authenticated && snapshot.source.found,
                    address: snapshot.source.as_slice(),
                },
                body: body_window,
            });
        }
        let mut event = [0; 256];
        if evaluation.action == PolicyAction::Allow {
            return Ok((evaluation.action, event, 0));
        }
        let mut site = Field::<96>::EMPTY;
        read_field(ensure_host(host)?, "site", &mut site)?;
        let site_text = core::str::from_utf8(site.as_slice()).unwrap_or("unknown");
        let event_len = evaluation
            .write_event(site_text, &mut event)
            .ok_or(AbiStatus::ResourceExhausted)?;
        Ok((evaluation.action, event, event_len))
    }

    fn read_field<const N: usize>(
        host: &mut WafHost,
        name: &str,
        output: &mut Field<N>,
    ) -> Result<(), AbiStatus> {
        let response = host.read_field(name).map_err(|error| error.status)?;
        output.set(response.value, response.found)
    }

    fn emit_observability(host: &mut WafHost, action: PolicyAction) -> Result<(), AbiStatus> {
        if action != PolicyAction::Allow {
            let event_action = if action == PolicyAction::Deny {
                nre_policy_guest::SecurityEventAction::Deny
            } else {
                nre_policy_guest::SecurityEventAction::Observe
            };
            host.emit_event(
                nre_policy_guest::SecurityEventCode::WafRuleMatch,
                event_action,
            )
            .map_err(|error| error.status)?;
        }
        Ok(())
    }

    fn ensure_host(host: &mut Option<WafHost>) -> Result<&mut WafHost, AbiStatus> {
        if host.is_none() {
            let current = HostClient::new(WasmHost, HostLimits::new(16, 256))
                .map_err(|error| error.status)?;
            *host = Some(current);
        }
        host.as_mut().ok_or(AbiStatus::Internal)
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
