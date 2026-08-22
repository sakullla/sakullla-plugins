#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

nre_policy_guest::export_incompatible_policy_guest!(
    "required trusted-source capability unavailable",
    "ip_policy_anchor"
);
