#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

nre_policy_guest::export_incompatible_policy_guest!(
    "required monotonic-clock and atomic-state capabilities unavailable",
    "rate_limit_anchor"
);
