/// Export a bounded canonical policy guest that always fails initialization
/// and evaluation with `IncompatibleAbi` while retaining the complete Host
/// import surface. This is intended for policy implementations whose required
/// typed Host capability is not yet available.
#[macro_export]
macro_rules! export_incompatible_policy_guest {
    ($message:expr, $metric:expr) => {
        const INPUT_BYTES: usize = 128 << 10;
        const OUTPUT_BYTES: usize = 4 << 10;

        struct SharedBuffer<const N: usize>(core::cell::UnsafeCell<[u8; N]>);

        // WebAssembly policy instances are single-threaded by contract. The
        // atomic flags still make ownership transitions explicit to Rust.
        unsafe impl<const N: usize> Sync for SharedBuffer<N> {}

        static INPUT: SharedBuffer<INPUT_BYTES> =
            SharedBuffer(core::cell::UnsafeCell::new([0; INPUT_BYTES]));
        static OUTPUT: SharedBuffer<OUTPUT_BYTES> =
            SharedBuffer(core::cell::UnsafeCell::new([0; OUTPUT_BYTES]));
        static INPUT_ACTIVE: core::sync::atomic::AtomicBool =
            core::sync::atomic::AtomicBool::new(false);
        static OUTPUT_ACTIVE: core::sync::atomic::AtomicBool =
            core::sync::atomic::AtomicBool::new(false);

        #[unsafe(no_mangle)]
        pub extern "C" fn nre_policy_version() -> u32 {
            $crate::ABI_MAJOR_VERSION
        }

        #[unsafe(no_mangle)]
        pub extern "C" fn nre_policy_alloc(size: u32) -> u32 {
            if size == 0
                || size as usize > INPUT_BYTES
                || INPUT_ACTIVE
                    .compare_exchange(
                        false,
                        true,
                        core::sync::atomic::Ordering::AcqRel,
                        core::sync::atomic::Ordering::Acquire,
                    )
                    .is_err()
            {
                return 0;
            }
            INPUT.0.get().cast::<u8>() as u32
        }

        #[unsafe(no_mangle)]
        pub extern "C" fn nre_policy_free(pointer: u32, length: u32) {
            if pointer == INPUT.0.get().cast::<u8>() as u32 && length as usize <= INPUT_BYTES {
                INPUT_ACTIVE.store(false, core::sync::atomic::Ordering::Release);
            } else if pointer == OUTPUT.0.get().cast::<u8>() as u32
                && length as usize <= OUTPUT_BYTES
            {
                OUTPUT_ACTIVE.store(false, core::sync::atomic::Ordering::Release);
            }
        }

        #[unsafe(no_mangle)]
        pub extern "C" fn nre_policy_init(pointer: u32, length: u32) -> u32 {
            let Ok(frame) = input_frame(pointer, length) else {
                return $crate::AbiStatus::InvalidArgument as u32;
            };
            let Ok(request) = $crate::InitRequest::decode(frame, $crate::WireLimits::POLICY_INPUT)
            else {
                return $crate::AbiStatus::InvalidArgument as u32;
            };
            if request.config.is_empty() || request.generation.is_empty() {
                return $crate::AbiStatus::InvalidArgument as u32;
            }
            $crate::AbiStatus::IncompatibleAbi as u32
        }

        #[unsafe(no_mangle)]
        pub extern "C" fn nre_policy_evaluate(pointer: u32, length: u32) -> u64 {
            if pointer == u32::MAX {
                retain_canonical_imports(length);
                return 0;
            }
            if input_frame(pointer, length).is_err()
                || OUTPUT_ACTIVE
                    .compare_exchange(
                        false,
                        true,
                        core::sync::atomic::Ordering::AcqRel,
                        core::sync::atomic::Ordering::Acquire,
                    )
                    .is_err()
            {
                return 0;
            }
            // SAFETY: OUTPUT_ACTIVE grants exclusive access until Host free.
            let output = unsafe { &mut *OUTPUT.0.get() };
            match $crate::encode_evaluate_error(
                output,
                $crate::RuntimeErrorCode::IncompatibleAbi,
                $message,
                false,
            ) {
                Ok(frame) => $crate::pack_policy_buffer(
                    OUTPUT.0.get().cast::<u8>() as u32,
                    frame.len() as u32,
                ),
                Err(_) => {
                    OUTPUT_ACTIVE.store(false, core::sync::atomic::Ordering::Release);
                    0
                }
            }
        }

        #[unsafe(no_mangle)]
        pub extern "C" fn nre_policy_reset() -> u32 {
            if INPUT_ACTIVE.load(core::sync::atomic::Ordering::Acquire)
                || OUTPUT_ACTIVE.load(core::sync::atomic::Ordering::Acquire)
            {
                $crate::AbiStatus::InvalidArgument as u32
            } else {
                $crate::AbiStatus::Ok as u32
            }
        }

        fn input_frame(pointer: u32, length: u32) -> Result<&'static [u8], ()> {
            if !INPUT_ACTIVE.load(core::sync::atomic::Ordering::Acquire)
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
            let Ok(mut host) = $crate::HostClient::<_, 256, 256>::new(
                $crate::WasmHost,
                $crate::HostLimits::new(2, 64),
            ) else {
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
                4 => {}
                _ => {
                    let _ = host.add_metric($metric, 0);
                }
            }
        }
    };
}
