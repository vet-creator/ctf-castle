/* The MONOLITH bytecode VM: decrypts the embedded program, derives the whole
 * key schedule from a tamper-evidence hash of that decrypted program, and
 * interprets it (control-flow flattened) over the 32-byte candidate. */
#ifndef MONO_VM_H
#define MONO_VM_H
#include <stddef.h>
#include <stdint.h>
#include "bytecode_def.h"   /* opcode enum + MONO_BC_MAX (constants only) */

/* Stream cipher used to hide the program in the binary. Key is seed-derived,
 * so this is obfuscation, not secrecy; encrypt and decrypt are the same op. */
void     mono_bc_crypt(uint8_t *data, size_t len);

/* Tamper constant = first 32 bits (LE) of SHA-256(clear-text program). */
uint32_t mono_bc_tamper_plain(const uint8_t *plain, size_t len);

/* Run the program on `in`; return 1 iff the transform equals `target`. */
int      mono_vm_check(const uint8_t *enc, size_t len,
                       const uint8_t in[32], const uint8_t target[32]);

/* Run the program on `state` in place, leaving the transformed value
 * (no comparison) -- used only by the self-tests. */
void     mono_vm_transform(const uint8_t *enc, size_t len, uint8_t state[32]);

#endif
