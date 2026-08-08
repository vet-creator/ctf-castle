#include "vm.h"
#include "spn.h"
#include "sha256.h"
#include <string.h>

/* ---- program (de/en)cryption -------------------------------------------- */

static void bc_keystream(uint8_t *ks, size_t len) {
    size_t off = 0; uint8_t ctr = 0;
    while (off < len) {
        uint8_t blk[32];
        sha256_ctx c; sha256_init(&c);
        sha256_update(&c, MONO_SEED, MONO_SEED_LEN);
        uint8_t dom = 'B';
        sha256_update(&c, &dom, 1);
        sha256_update(&c, &ctr, 1);
        sha256_final(&c, blk);
        size_t take = len - off; if (take > 32) take = 32;
        memcpy(ks + off, blk, take);
        off += take; ctr++;
    }
}

void mono_bc_crypt(uint8_t *data, size_t len) {
    uint8_t ks[MONO_BC_MAX];
    if (len > MONO_BC_MAX) return;
    bc_keystream(ks, len);
    for (size_t i = 0; i < len; i++) data[i] ^= ks[i];
}

uint32_t mono_bc_tamper_plain(const uint8_t *plain, size_t len) {
    uint8_t h[32];
    sha256(plain, len, h);
    return (uint32_t)h[0] | ((uint32_t)h[1] << 8) |
           ((uint32_t)h[2] << 16) | ((uint32_t)h[3] << 24);
}

/* ---- obfuscation helpers ------------------------------------------------- */

/* opaque-true: n*(n+1) is always even, so its low bit is always 0. */
static int opaque_true(uint32_t n) { return (int)(((n * (n + 1u)) & 1u) == 0u); }

/* constant-ish equality with an MBA-rewritten XOR: a^b == (a|b)-(a&b). */
static int ct_equal(const uint8_t *a, const uint8_t *b, size_t n) {
    uint32_t acc = 0;
    for (size_t i = 0; i < n; i++) {
        uint32_t x = (uint32_t)((a[i] | b[i]) - (a[i] & b[i])); /* == a^b */
        acc |= x;
    }
    return (int)((acc | (~acc + 1u)) >> 31 ^ 1u) & 1; /* 1 iff acc==0 */
}

/* opcode -> dispatcher state */
static int decode(uint8_t op) {
    switch (op) {
        case OP_ARK: return 2;
        case OP_SUB: return 3;
        case OP_PMT: return 4;
        case OP_MIX: return 5;
        case OP_FEI: return 6;
        case OP_END: return 7;
        default:     return 0;   /* NOP / unknown -> keep fetching */
    }
}

/* ---- the interpreter (control-flow flattened) --------------------------- */

/* If `target` is non-NULL, returns 1/0 for match. If NULL, leaves the
 * transformed state in s[] and returns 0. */
static int run(const uint8_t *enc, size_t len, uint8_t s[32],
               const uint8_t *target) {
    uint8_t bc[MONO_BC_MAX];
    if (len == 0 || len > MONO_BC_MAX) return 0;
    memcpy(bc, enc, len);
    mono_bc_crypt(bc, len);                       /* decrypt in place        */

    uint32_t tamper = mono_bc_tamper_plain(bc, len);
    mono_ctx ctx; mono_ctx_build(&ctx, tamper);   /* keys bound to program   */

    size_t pc = 0;
    uint8_t imm = 0;
    int state = 1;                                 /* 1 = FETCH               */
    int result = 0;
    uint32_t guard = 0;

    while (state) {
        switch (state) {
            case 1: {                              /* FETCH + DECODE          */
                if (pc >= len) { state = 0; break; }
                uint8_t op = bc[pc++];
                if (opaque_true(guard)) guard += op; /* opaque no-op sink     */
                state = decode(op);
                break;
            }
            case 2:                                /* ARK imm                 */
                imm = bc[pc++];
                mono_op_addkey(&ctx, s, (int)imm);
                state = 1; break;
            case 3:                                /* SUB                     */
                mono_op_sub(s);
                state = 1; break;
            case 4:                                /* PMT                     */
                mono_op_perm(&ctx, s);
                state = 1; break;
            case 5:                                /* MIX                     */
                mono_op_mix(s);
                state = 1; break;
            case 6:                                /* FEI imm                 */
                imm = bc[pc++];
                mono_op_feistel(&ctx, s, (int)imm);
                state = 1; break;
            case 7:                                /* END                     */
                if (target) result = ct_equal(s, target, 32);
                state = 0; break;
            default:
                state = 0; break;
        }
    }
    (void)guard;
    return result;
}

int mono_vm_check(const uint8_t *enc, size_t len,
                  const uint8_t in[32], const uint8_t target[32]) {
    uint8_t s[32];
    memcpy(s, in, 32);
    return run(enc, len, s, target);
}

void mono_vm_transform(const uint8_t *enc, size_t len, uint8_t state[32]) {
    (void)run(enc, len, state, NULL);
}
