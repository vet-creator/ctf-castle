/* The PLAIN verification program for the MONOLITH VM.
 *
 * This file is linked into the build tools (generator, solver, self-tests)
 * but deliberately NOT into the shipped challenge binary, so the clear-text
 * program never appears in monolith.exe -- only its encrypted form (emitted
 * into generated/mono_data.h) does. */
#ifndef MONO_BYTECODE_DEF_H
#define MONO_BYTECODE_DEF_H
#include <stddef.h>
#include <stdint.h>

/* Opcodes (shared with the interpreter in vm.h). */
enum {
    OP_NOP = 0x00,
    OP_ARK = 0xA7,   /* + 1 immediate: SPN round-key index          */
    OP_SUB = 0x5B,   /* SubBytes                                     */
    OP_PMT = 0x3D,   /* byte permutation                            */
    OP_MIX = 0x6C,   /* MixColumns                                  */
    OP_FEI = 0xF1,   /* + 1 immediate: Feistel round-key index      */
    OP_END = 0xE9    /* compare state with target, halt             */
};

#define MONO_BC_MAX 512

/* Emit the clear-text program into out[] (>= MONO_BC_MAX). Returns length. */
size_t mono_bc_emit(uint8_t *out);
/* Program length. */
size_t mono_bc_len(void);

#endif
