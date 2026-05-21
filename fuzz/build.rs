// fuzz/build.rs
//
// Provides `sys_alloc_aligned` for non-RISC-V host targets.
//
// `risc0_zkvm_platform::syscall::sys_alloc_words` calls the bare-metal symbol
// `sys_alloc_aligned`, which is normally supplied by the RISC-V zkVM runtime.
// When compiling fuzz targets for a host target (x86_64-unknown-linux-gnu,
// aarch64-unknown-linux-gnu, …) that symbol is absent, causing a linker error.
// This build script compiles a small C stub via the `cc` crate so the symbol
// is always available in the final fuzz binary.
//
// On macOS host builds (used by `cargo fuzz` / libFuzzer) the `cc` crate
// compiles the same stub; it is harmlessly dead-stripped if the symbol is not
// referenced.

fn main() {
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    // RISC-V builds get the real symbol from the zkVM runtime — skip the stub.
    if target_arch != "riscv32" && target_arch != "riscv64" {
        cc::Build::new()
            .file("build_stubs/sys_alloc_aligned.c")
            .compile("sys_alloc_stub");
    }
}
