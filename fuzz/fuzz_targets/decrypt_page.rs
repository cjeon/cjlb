#![no_main]
use libfuzzer_sys::fuzz_target;
use cjlb_crypto::decrypt_page;

fuzz_target!(|data: &[u8]| {
    // Fixed key and bundle_id for deterministic fuzzing
    let key = [0x42u8; 32];
    let bundle_id = [0xDE; 16];

    // decrypt_page should gracefully handle any input without panicking
    let _ = decrypt_page(data, &key, &bundle_id);
});
