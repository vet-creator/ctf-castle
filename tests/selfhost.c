/* Comprehensive correctness gate (run by CI on every push).
 * Returns non-zero if anything is wrong. */
#include <stdio.h>
#include <string.h>
#include "sha256.h"
#include "gf.h"
#include "spn.h"
#include "vm.h"
#include "bytecode_def.h"
#include "generated/mono_data.h"

static int fails = 0;
#define CHECK(cond, name) do { \
    int _c = (cond); \
    printf("  [%s] %s\n", _c ? "PASS" : "FAIL", name); \
    if (!_c) fails++; \
} while (0)

int main(void) {
    printf("MONOLITH self-test\n------------------\n");

    /* --- primitives --- */
    {
        uint8_t d[32]; char got[65];
        sha256("abc", 3, d);
        for (int i = 0; i < 32; i++) sprintf(got + 2*i, "%02x", d[i]);
        CHECK(strcmp(got,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0,
            "SHA-256(\"abc\") known answer");
    }
    gf_init();
    CHECK(gf_sbox(0x00)==0x63 && gf_sbox(0x53)==0xed, "AES S-box values");
    {
        int inv = 1; for (int i=0;i<256;i++) if (gf_inv_sbox(gf_sbox(i))!=i) inv=0;
        CHECK(inv, "inverse S-box round-trips");
    }
    {
        int mc = 1;
        for (int t=0;t<64;t++){ uint8_t s[32],o[32];
            for(int i=0;i<32;i++) s[i]=(uint8_t)(i*7+t*31+13);
            memcpy(o,s,32); gf_mixcolumns(s); gf_inv_mixcolumns(s);
            if (memcmp(s,o,32)) mc=0; }
        CHECK(mc, "MixColumns invertible");
    }

    /* --- cipher core --- */
    {
        mono_ctx c; mono_ctx_build(&c, 0xA5A5A5A5u);
        int seen[32]={0}, bij=1;
        for(int i=0;i<32;i++){ if(c.P[i]>=32||seen[c.P[i]]) bij=0; else seen[c.P[i]]=1; }
        int pinv=1; for(int i=0;i<32;i++) if(c.Pinv[c.P[i]]!=i) pinv=0;
        CHECK(bij && pinv, "permutation is a bijection with correct inverse");

        int rt = 1;
        for(uint32_t tv=0; tv<6 && rt; tv++){
            mono_ctx k; mono_ctx_build(&k, tv*0x11111111u + 3u);
            for(int t=0;t<1500;t++){ uint8_t s[32],o[32];
                for(int i=0;i<32;i++) s[i]=(uint8_t)((i*131+t*17+tv*7)&0xff);
                memcpy(o,s,32); mono_forward(&k,s); mono_inverse(&k,s);
                if(memcmp(s,o,32)){ rt=0; break; } } }
        CHECK(rt, "forward/inverse round-trip over many vectors");
    }

    /* --- VM equivalence + semantics --- */
    {
        uint8_t plain[MONO_BC_MAX]; size_t len = mono_bc_emit(plain);
        uint32_t tamper = mono_bc_tamper_plain(plain, len);
        mono_ctx ctx; mono_ctx_build(&ctx, tamper);
        uint8_t enc[MONO_BC_MAX]; memcpy(enc, plain, len); mono_bc_crypt(enc, len);

        int eq = 1;
        for(int t=0;t<3000 && eq;t++){ uint8_t in[32],ref[32],vm[32];
            for(int i=0;i<32;i++) in[i]=(uint8_t)((i*97+t*41+7)&0xff);
            memcpy(ref,in,32); mono_forward(&ctx,ref);
            memcpy(vm,in,32); mono_vm_transform(enc,len,vm);
            if(memcmp(ref,vm,32)) eq=0; }
        CHECK(eq, "VM transform == reference forward");

        uint8_t in[32],tgt[32];
        for(int i=0;i<32;i++) in[i]=(uint8_t)(i*13+5);
        memcpy(tgt,in,32); mono_forward(&ctx,tgt);
        uint8_t bad[32]; memcpy(bad,tgt,32); bad[9]^=0x40;
        CHECK(mono_vm_check(enc,len,in,tgt)==1, "VM accepts correct target");
        CHECK(mono_vm_check(enc,len,in,bad)==0, "VM rejects wrong target");

        uint8_t enc2[MONO_BC_MAX]; memcpy(enc2,enc,len); enc2[4]^=1;
        CHECK(mono_vm_check(enc2,len,in,tgt)==0, "patched bytecode breaks (tamper-evident)");
    }

    /* --- embedded challenge is self-consistent + solvable --- */
    {
        uint8_t bc[MONO_ENC_BC_LEN];
        memcpy(bc, MONO_ENC_BC, MONO_ENC_BC_LEN);
        mono_bc_crypt(bc, MONO_ENC_BC_LEN);
        uint32_t tamper = mono_bc_tamper_plain(bc, MONO_ENC_BC_LEN);
        mono_ctx ctx; mono_ctx_build(&ctx, tamper);

        uint8_t flag[MONO_BLOCK];
        memcpy(flag, MONO_TARGET, MONO_BLOCK);
        mono_inverse(&ctx, flag);

        int printable = 1;
        for (int i=0;i<MONO_BLOCK;i++) if (flag[i]<0x20||flag[i]>0x7e) printable=0;
        CHECK(printable, "recovered flag is printable ASCII");

        uint8_t v[MONO_BLOCK]; memcpy(v, flag, MONO_BLOCK); mono_forward(&ctx, v);
        CHECK(memcmp(v, MONO_TARGET, MONO_BLOCK)==0, "forward(recovered) == target");

        CHECK(mono_vm_check(MONO_ENC_BC, MONO_ENC_BC_LEN, flag, MONO_TARGET)==1,
              "VM accepts the recovered flag");
    }

    printf("------------------\n%s\n", fails ? "SELFTEST FAILED" : "ALL SELFTESTS PASSED");
    return fails ? 1 : 0;
}
