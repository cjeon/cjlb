#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use cjlb_format::nonce::make_nonce;

#[derive(Arbitrary, Debug)]
struct Input {
    domain1: u32,
    counter1: u64,
    domain2: u32,
    counter2: u64,
}

fuzz_target!(|input: Input| {
    let n1 = make_nonce(input.domain1, input.counter1);
    let n2 = make_nonce(input.domain2, input.counter2);

    // Nonces should only be equal if both domain AND counter are equal
    if input.domain1 == input.domain2 && input.counter1 == input.counter2 {
        assert_eq!(n1, n2);
    } else {
        assert_ne!(
            n1, n2,
            "nonce collision: domain ({}, {}) counter ({}, {})",
            input.domain1, input.domain2, input.counter1, input.counter2
        );
    }
});
