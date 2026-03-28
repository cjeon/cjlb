#![no_main]
use libfuzzer_sys::fuzz_target;
use cjlb_format::config::ClientConfig;

fuzz_target!(|data: &[u8]| {
    // Try parsing as JSON
    if let Ok(mut config) = serde_json::from_slice::<ClientConfig>(data) {
        // Validate should never panic
        let _ = config.validate();
    }
});
