use std::fs;
use std::path::Path;

#[test]
fn generate_seeds() {
    let tx = common::test_utils::produce_dummy_empty_transaction();
    let bytes = borsh::to_vec(&tx).unwrap();

    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("fuzz_props is one level below the workspace root");

    let targets = [
        "fuzz/corpus/fuzz_transaction_decoding/seed_empty_tx",
        "fuzz/corpus/fuzz_stateless_verification/seed_empty_tx",
        "fuzz/corpus/fuzz_state_transition/seed_empty_tx",
    ];
    for rel in &targets {
        let p = workspace_root.join(rel);
        if let Some(parent) = p.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(&p, &bytes);
    }
}
