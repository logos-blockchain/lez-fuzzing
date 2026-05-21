#![cfg_attr(feature = "fuzzer-libfuzzer", no_main)]
// use fuzz_props::arbitrary_types::*;
// use fuzz_props::generators::*;
// use fuzz_props::invariants::*;

fuzz_props::fuzz_entry!(|data: &[u8]| {
    // TODO: implement harness body
    let _ = data;
});
