# MONOLITH — 黒曜の碑

A **reverse-engineering CTF** where *the compiled binary itself is the target*.
`monolith.exe` reads one line — `MONOLITH{……32 chars……}` — and tells you whether
it is the single input that the embedded transform maps to the embedded target.
There is exactly one accepting input. Finding it means **reversing**, not guessing
and not brute-forcing (the search space is 2²⁵⁶).

> **これは何？** ビルドすると Windows 用コンソールアプリ `monolith.exe` が生成されます。
> そのアプリ自身が攻略対象（crackme / リバースエンジニアリング課題）です。正解の
> フラグを 1 つだけ受理します。総当たりでは解けません（鍵空間 2²⁵⁶）。解答は「実行
> バイナリを解析して変換を復元し、逆算する」ことでのみ得られます。

---

## 🛡️ Safety / 安全性について

This is a **puzzle**, not an attack tool. The binary is deliberately benign:

* No network. No file writes. No registry, process, memory-injection, or
  persistence behavior. Its only syscalls read `stdin`, write `stdout`, and (on
  Windows) switch the console to UTF-8 + ANSI.
* Its imports are just the C runtime and console functions — nothing that
  antivirus heuristics associate with malware.
* Every "hard" mechanism here (a bytecode **VM**, a **substitution-permutation
  network**, a **Feistel/ARX** stage, mixed-boolean-arithmetic, control-flow
  flattening, tamper-evidence) is a standard *software-protection / obfuscation*
  technique. None of it does anything to any system.

> 攻撃的な機能は一切含みません。ネットワーク・ファイル書き込み・プロセス注入・レジ
> ストリ操作などは行わず、標準入出力とコンソール設定のみを使用します。難読化・VM・
> 暗号（SPN / Feistel）はすべて防御的なソフトウェア保護技術で、外部に害を及ぼしません。

---

## How to play / 遊び方

Run it, paste a candidate flag, press Enter:

```
$ monolith.exe
  seal> MONOLITH{................................}
```

Right input → **“THE MONOLITH OPENS.”** Wrong input → rejected.

---

## What a solver has to reverse

The check is a fixed **bijection** on a 256-bit block, expressed as a program for
a small custom VM. To recover the one accepting input you must peel these layers:

1. **Custom bytecode VM (devirtualization).**
   The verification logic runs on a register VM with a *control-flow-flattened*
   dispatcher and non-standard opcodes. You must reconstruct the instruction set
   and the program.
2. **Encrypted program + tamper evidence.**
   The bytecode is stored XOR-encrypted (seed-derived keystream). At run time it
   is decrypted and **hashed**; that hash seeds the *entire* key schedule. Patch
   a single program byte and every derived key changes — the target no longer
   matches. You cannot "nop out" the check; you must actually invert it.
3. **Nothing is a static magic constant.**
   The S-box, the GF(2⁸) tables, the byte permutation, and all round keys are
   **derived at run time** from a 128-bit seed via SHA-256. Grepping the binary
   for known tables gets you nothing; you must emulate the derivation.
4. **Two structurally different cipher stages, in series.**
   * **SPN** — `R1=12` rounds of AddRoundKey → SubBytes → Permute → MixColumns
     (AES-style GF(2⁸) primitives, but custom permutation, custom key schedule,
     uniform rounds).
   * **Feistel** — `R2=12` rounds with an **ARX** round function
     (add / rotate / xor over 32-bit words).
   Both are individually invertible, so once fully recovered the flag drops out
   by running the chain backwards — which is exactly what the reference solver in
   `tools/solver.c` does, using only data present in the shipped binary.

Difficulty is dominated by **effort and breadth** (devirtualize → recover four
derived structures → reconstruct both ciphers → implement the inverse), not by
any single computationally-infeasible step. That keeps it *hard but solvable*,
which is what a good CTF needs.

> 難易度の本質は「VM のデバーチャライズ → 実行時導出テーブル/鍵の復元 → 2 種類の暗号
> 構造（SPN と Feistel/ARX）の再構成 → 逆変換の実装」という作業量と広さにあります。
> 計算量的に不可能なステップは無いので、正しく解析すれば必ず解けます。

---

## Repository layout

```
MONOLITH/
├─ CMakeLists.txt              build (generator → challenge → solver → tests)
├─ .github/workflows/build.yml CI: MSVC build + tests + monolith.exe artifact
├─ src/
│  ├─ sha256.{h,c}             SHA-256 (all derivation + tamper hash)
│  ├─ gf.{h,c}                 GF(2⁸): runtime S-box / MixColumns
│  ├─ spn.{h,c}               cipher core: key schedule, SPN + Feistel, forward/inverse
│  ├─ vm.{h,c}                 flattened bytecode interpreter + program (de)cryption
│  ├─ bytecode_def.{h,c}       CLEAR program (linked into tools/tests only)
│  └─ main.c                   the challenge front-end  →  monolith.exe
├─ tools/
│  ├─ generator.c             build-time: writes generated/mono_data.h
│  └─ solver.c                reference solver (proves solvability; designer tool)
└─ tests/
   ├─ selftest.c              13 correctness checks (KATs, round-trips, VM==ref, …)
   └─ integration.cmake       end-to-end: solver flag accepted, mutated flag rejected
```

**Important:** the clear-text program (`bytecode_def.c`) and the flag are **never**
linked into `monolith.exe`. The generator computes `target = forward(flag)` and
emits `generated/mono_data.h` containing only the *encrypted* program and the
*target*. The shipped binary contains the puzzle, not the answer.

---

## Build with GitHub Actions

Push the repo. The **build** workflow:

* builds `monolith.exe` with MSVC on `windows-latest`,
* runs the self-test **and** the end-to-end test (`ctest`),
* also builds+tests on Linux for portability,
* uploads **`monolith-windows-x64`** (the `monolith.exe` artifact).

Download the artifact from the workflow run — that is the file you hand to players.

## Build locally

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build --output-on-failure     # 13 self-tests + integration
```

Windows binary: `build/Release/monolith.exe`.

## Set your own flag / 独自のフラグ設定

The inner content must be **exactly 32 characters**. Either edit `DEFAULT_INNER`
in `tools/generator.c`, or set an environment variable at configure time:

```bash
MONO_FLAG_INNER='your_exactly_32_character_secret' cmake -B build
```

In CI, add a repository secret `MONO_FLAG_INNER` (the workflow already forwards
it). **Keep your flag / this repo private and distribute only `monolith.exe`.**
The default flag shipped here is public on purpose (for CI/demo).

## Verify it is solvable

`tools/solver.c` reverses the transform using *only* the encrypted program and
the target embedded in the binary (exactly what a player who fully reversed the
VM would do), and prints the flag:

```bash
./build/mono_solver          # -> MONOLITH{...}
```

This is a **designer** tool — don't publish it alongside the challenge.

---

## Honest notes on difficulty & further hardening

"World-hardest" is aspirational — real difficulty depends on the solver, tooling,
and time. This design is built to be *genuinely* tough while remaining correct,
buildable, and verifiably solvable. If you want more resistance, layer these on
top (all still non-offensive):

* Compile with an obfuscator (LLVM-Obfuscator / Tigress / commercial VM packers)
  for opaque predicates and instruction-level virtualization on the *primitives*
  themselves.
* Add finer-grained (per-byte) opcodes so the SPN/Feistel structure is not
  visible at operation granularity.
* Add anti-debugging **only if** you are willing to accept AV false-positive risk
  and reduced portability (intentionally omitted here for clean distribution).
* Add an extra math gate (e.g. a discrete-log or lattice constraint over part of
  the input) if you want a cryptanalytic sub-puzzle in addition to reversing.

## License

MIT — see [LICENSE](LICENSE).
