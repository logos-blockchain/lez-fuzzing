/*
 * sys_alloc_aligned.c
 *
 * Provides `sys_alloc_aligned` for non-RISC-V host targets
 * (e.g. aarch64-unknown-linux-gnu, x86_64-unknown-linux-gnu).
 *
 * On RISC-V the real symbol is supplied by the zkVM bare-metal runtime.
 * On host targets, risc0_zkvm_platform may still reference this symbol via
 * its `sys_alloc_words` helper; this stub satisfies that reference using
 * POSIX `posix_memalign`.
 */
#ifndef __riscv

#include <stddef.h>
#include <stdlib.h>

void *sys_alloc_aligned(size_t bytes, size_t align) {
    void *ptr = NULL;
    /* posix_memalign requires alignment >= sizeof(void*) and a power of 2. */
    size_t real_align = align < sizeof(void *) ? sizeof(void *) : align;
    if (posix_memalign(&ptr, real_align, bytes) != 0)
        return NULL;
    return ptr;
}

#endif /* !__riscv */
