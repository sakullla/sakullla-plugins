#![forbid(unsafe_code)]

//! Keeps the `plugins/*` workspace glob valid before the first policy guest.

/// Marker used by the repository-foundation test.
pub const WORKSPACE_READY: bool = true;

#[cfg(test)]
mod tests {
    use super::WORKSPACE_READY;

    #[test]
    fn workspace_anchor_is_ready() {
        assert!(WORKSPACE_READY);
    }
}
