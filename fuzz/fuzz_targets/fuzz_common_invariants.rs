#![cfg_attr(feature = "fuzzer-libfuzzer", no_main)]
//! Fuzz target: common-crate and low-level type invariants.
//!
//! This target is **input-independent**: the fuzz input is always ignored.
//! It asserts deterministic invariants about types in `lez/common` and
//! low-level `lee` types that are not exercised by higher-level state-transition
//! targets.
//!
//! # Corpus note
//!
//! A single `\x00` seed file is sufficient — the input bytes are never read.

use common::{HashType, config::BasicAuth};
use nssa::{
    privacy_preserving_transaction::circuit::Proof,
    program::Program,
    program_deployment_transaction::Message as DeployMessage,
    program_methods::{
        AUTHENTICATED_TRANSFER_ELF, TOKEN_ELF,
    },
};

fuzz_props::fuzz_entry!(|_data: &[u8]| {
    // ── INVARIANT [HashTypeAsRefLength] ────────────────────────────────────────
    // `HashType::as_ref()` must always return exactly 32 bytes.
    // Catches mutations that return an empty slice or a slice of the wrong size.
    let all_ones = HashType([1_u8; 32]);
    assert_eq!(
        all_ones.as_ref().len(),
        32,
        "INVARIANT VIOLATION [HashTypeAsRefLength]: HashType::as_ref must return 32 bytes",
    );

    let zero = HashType::default();
    assert_eq!(
        zero.as_ref().len(),
        32,
        "INVARIANT VIOLATION [HashTypeAsRefLength]: HashType::as_ref on default must return 32 bytes",
    );

    // ── INVARIANT [HashTypeAsRefBytes] ────────────────────────────────────────
    // `HashType::as_ref()` must return the exact inner bytes.
    // Catches mutations that return `vec![0]` or `vec![1]` instead of `&self.0`.
    let known = [0x42_u8; 32];
    let hash = HashType(known);
    assert_eq!(
        hash.as_ref(),
        &known,
        "INVARIANT VIOLATION [HashTypeAsRefBytes]: HashType::as_ref must return the inner [u8;32]",
    );

    // ── INVARIANT [BasicAuthPasswordPreserved] ───────────────────────────────
    // Parsing "user:password" must preserve the non-empty password as `Some`.
    // Catches the mutation that deletes `!` in the `.filter(|p| !p.is_empty())`
    // predicate, which would flip the logic and accept only empty passwords.
    let auth: BasicAuth = "user:secret"
        .parse()
        .expect("INVARIANT VIOLATION: 'user:secret' must parse as BasicAuth");
    assert_eq!(
        auth.password.as_deref(),
        Some("secret"),
        "INVARIANT VIOLATION [BasicAuthPasswordPreserved]: \
         parsing 'user:secret' must give password = Some(\"secret\")",
    );

    let auth2: BasicAuth = "alice:hunter2"
        .parse()
        .expect("INVARIANT VIOLATION: 'alice:hunter2' must parse");
    assert_eq!(
        auth2.password.as_deref(),
        Some("hunter2"),
        "INVARIANT VIOLATION [BasicAuthPasswordPreserved]: \
         password must match the part after the colon",
    );

    // ── INVARIANT [BasicAuthEmptyPasswordIsNone] ─────────────────────────────
    // Parsing "user:" (empty password) must give `password = None`.
    // With the `!` deleted, this would become `Some("")` instead of `None`.
    let auth_empty: BasicAuth = "user:"
        .parse()
        .expect("INVARIANT VIOLATION: 'user:' must parse as BasicAuth");
    assert_eq!(
        auth_empty.password,
        None,
        "INVARIANT VIOLATION [BasicAuthEmptyPasswordIsNone]: \
         an empty password (trailing colon) must give password = None",
    );

    // ── INVARIANT [ProgramElfNonEmpty] ───────────────────────────────────────
    // `Program::elf()` must return a non-empty byte slice.
    // Catches the mutation that returns `Vec::leak(Vec::new())`.
    let at_prog = Program::authenticated_transfer_program();
    assert!(
        !at_prog.elf().is_empty(),
        "INVARIANT VIOLATION [ProgramElfNonEmpty]: \
         Program::authenticated_transfer_program().elf() must not be empty",
    );

    let token_prog = Program::token();
    assert!(
        !token_prog.elf().is_empty(),
        "INVARIANT VIOLATION [ProgramElfNonEmpty]: \
         Program::token().elf() must not be empty",
    );

    // ── INVARIANT [ProgramElfCorrect] ────────────────────────────────────────
    // `Program::elf()` must return exactly the compile-time bytecode constant.
    // Catches the mutations that return `vec![0]` or `vec![1]`.
    assert_eq!(
        at_prog.elf(),
        AUTHENTICATED_TRANSFER_ELF,
        "INVARIANT VIOLATION [ProgramElfCorrect]: \
         Program::authenticated_transfer_program().elf() must equal AUTHENTICATED_TRANSFER_ELF",
    );

    assert_eq!(
        token_prog.elf(),
        TOKEN_ELF,
        "INVARIANT VIOLATION [ProgramElfCorrect]: \
         Program::token().elf() must equal TOKEN_ELF",
    );

    // ── INVARIANT [ProofIntoInnerRoundtrip] ──────────────────────────────────
    // `Proof::from_inner(bytes).into_inner()` must return the original bytes.
    // Catches the mutations that return `vec![]`, `vec![0]`, or `vec![1]`.
    let proof_bytes = vec![0xDE_u8, 0xAD, 0xBE, 0xEF];
    let proof = Proof::from_inner(proof_bytes.clone());
    assert_eq!(
        proof.into_inner(),
        proof_bytes,
        "INVARIANT VIOLATION [ProofIntoInnerRoundtrip]: \
         Proof::from_inner(b).into_inner() must return b",
    );

    // Also test with an empty proof (round-trip must preserve emptiness).
    let empty_proof = Proof::from_inner(vec![]);
    assert!(
        empty_proof.into_inner().is_empty(),
        "INVARIANT VIOLATION [ProofIntoInnerRoundtrip]: \
         empty Proof::from_inner(vec![]).into_inner() must be empty",
    );

    // And with a single non-zero byte:
    let single = Proof::from_inner(vec![0xFF]);
    assert_eq!(
        single.into_inner(),
        vec![0xFF_u8],
        "INVARIANT VIOLATION [ProofIntoInnerRoundtrip]: \
         Proof from single byte must round-trip correctly",
    );

    // ── INVARIANT [DeployMessageBytecodeRoundtrip] ────────────────────────────
    // `Message::new(bytecode).into_bytecode()` must return the original bytecode.
    // Catches the mutations that return `vec![]`, `vec![0]`, or `vec![1]`.
    let bytecode = vec![0x7F_u8, 0x45, 0x4C, 0x46]; // ELF magic
    let msg = DeployMessage::new(bytecode.clone());
    assert_eq!(
        msg.into_bytecode(),
        bytecode,
        "INVARIANT VIOLATION [DeployMessageBytecodeRoundtrip]: \
         Message::new(b).into_bytecode() must return b",
    );

    // Empty bytecode round-trip:
    let empty_msg = DeployMessage::new(vec![]);
    assert!(
        empty_msg.into_bytecode().is_empty(),
        "INVARIANT VIOLATION [DeployMessageBytecodeRoundtrip]: \
         empty bytecode must round-trip as empty",
    );
});
