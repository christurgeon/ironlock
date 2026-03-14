/// Attempts to lock a memory region to prevent it from being swapped to disk.
/// This is a best-effort operation — failures are silently ignored since
/// mlock may fail due to resource limits (RLIMIT_MEMLOCK) on some systems.
#[cfg(unix)]
pub fn mlock_slice(data: &[u8]) {
    unsafe {
        libc::mlock(data.as_ptr() as *const libc::c_void, data.len());
    }
}

/// Unlocks a previously locked memory region, allowing it to be swapped again.
/// This is a best-effort operation — failures are silently ignored.
#[cfg(unix)]
#[allow(dead_code)]
pub fn munlock_slice(data: &[u8]) {
    unsafe {
        libc::munlock(data.as_ptr() as *const libc::c_void, data.len());
    }
}

#[cfg(not(unix))]
pub fn mlock_slice(_data: &[u8]) {
    // No-op on non-Unix platforms
}

#[cfg(not(unix))]
#[allow(dead_code)]
pub fn munlock_slice(_data: &[u8]) {
    // No-op on non-Unix platforms
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mlock_unlock_roundtrip() {
        let data = [1u8, 2, 3, 4, 5, 6, 7, 8];
        mlock_slice(&data);
        munlock_slice(&data);
        // Should complete without panicking
    }

    #[test]
    fn test_mlock_empty_slice() {
        let data: [u8; 0] = [];
        mlock_slice(&data);
        munlock_slice(&data);
        // Locking an empty slice should not panic
    }

    #[test]
    fn test_mlock_large_allocation() {
        let data = vec![0xABu8; 4096];
        mlock_slice(&data);
        munlock_slice(&data);
        // Locking a large buffer should not panic
    }
}
