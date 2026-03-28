#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use cjlb_crypto::{decrypt_page, encrypt_page};
use cjlb_format::nonce::make_nonce;
use cjlb_format::page::PAGE_BODY_SIZE;

#[derive(Arbitrary, Debug)]
struct Input {
    plaintext_len: usize, // will be clamped to PAGE_BODY_SIZE
    key_seed: u8,
    nonce_counter: u64,
}

fuzz_target!(|input: Input| {
    let len = input.plaintext_len % (PAGE_BODY_SIZE + 1);
    let plaintext: Vec<u8> = (0..len).map(|i| (i & 0xFF) as u8).collect();
    let key = [input.key_seed; 32];
    let bundle_id = [0xAB; 16];
    let nonce = make_nonce(1, input.nonce_counter);

    let encrypted = match encrypt_page(&plaintext, &key, &nonce, &bundle_id) {
        Ok(e) => e,
        Err(_) => return,
    };

    let decrypted =
        decrypt_page(&encrypted, &key, &bundle_id).expect("decrypting our own ciphertext must succeed");

    // Decrypted should contain our plaintext (may be padded to 4KB quantum)
    assert!(decrypted.len() >= plaintext.len());
    assert_eq!(&decrypted[..plaintext.len()], &plaintext[..]);
});
