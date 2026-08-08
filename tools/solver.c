/* Reference solver.
 *
 * Uses ONLY what is present in the shipped binary -- the encrypted program and
 * the target -- exactly as an attacker who has fully reversed the VM would:
 *
 *   1. decrypt the embedded program (key is seed-derived);
 *   2. hash it to recover the tamper constant;
 *   3. rebuild the derived key schedule / tables;
 *   4. invert the two-stage transform on the target.
 *
 * This exists to PROVE the challenge is solvable and to give CI a source of the
 * correct flag. It does not read the clear-text program or the secret flag. */
#include <stdio.h>
#include <string.h>
#include "spn.h"
#include "vm.h"
#include "generated/mono_data.h"

int main(void) {
    /* (1) decrypt embedded program */
    uint8_t bc[MONO_ENC_BC_LEN];
    memcpy(bc, MONO_ENC_BC, MONO_ENC_BC_LEN);
    mono_bc_crypt(bc, MONO_ENC_BC_LEN);

    /* (2) tamper constant from the decrypted program */
    uint32_t tamper = mono_bc_tamper_plain(bc, MONO_ENC_BC_LEN);

    /* (3) rebuild schedule */
    mono_ctx ctx; mono_ctx_build(&ctx, tamper);

    /* (4) invert the target */
    uint8_t s[MONO_BLOCK];
    memcpy(s, MONO_TARGET, MONO_BLOCK);
    mono_inverse(&ctx, s);

    /* sanity: forward again must reproduce the target */
    uint8_t v[MONO_BLOCK];
    memcpy(v, s, MONO_BLOCK);
    mono_forward(&ctx, v);
    int ok = (memcmp(v, MONO_TARGET, MONO_BLOCK) == 0);

    int printable = 1;
    for (int i = 0; i < MONO_BLOCK; i++)
        if (s[i] < 0x20 || s[i] > 0x7e) printable = 0;

    if (ok && printable) {
        printf("MONOLITH{");
        fwrite(s, 1, MONO_BLOCK, stdout);
        printf("}\n");
        return 0;
    }
    fprintf(stderr, "solver failed (ok=%d printable=%d)\n", ok, printable);
    return 1;
}
