# wolfssl-compliance-tooling — Product × Front-End SBOM Matrix

This document maps each wolfSSL product to the build systems it ships, the SBOM
composition method, and the constraints. It is the companion to `PLAN.md`. It
follows ASD-STE100 Simplified Technical English.

The roster and the tiers come from the wolfSSL Family Supported-Platforms matrix.
The front-end family, the composition flavor, and the constraints come from the
wolfssl-compliance-tooling two-axis model.

Facts marked with a check are verified in the local workspace. Facts marked with
a cross are not in this checkout; verify them in the source checkout before you
attest them.

## 1. How to read the matrix

An SBOM needs two independent inputs. The matrix uses two axes for them.

- Axis 1 is the config. It records what features the build enabled.
- Axis 2 is the composition. It records what artifact the build produced.

A product also uses one or more front ends. A front end is the build-system
adapter that produces the two inputs. One product can use many front ends.

## 2. Legend

Front-end codes:

| Code | Meaning |
|---|---|
| `A` | Autotools (`configure` + `Makefile.am`). |
| `C` | CMake. |
| `M` | Make or `arch.mk`. |
| `IAR` | IAR Embedded Workbench project (`.ewp`). |
| `CDB` | Compilation database (`compile_commands.json`). |
| `RT` | Route-through (a wrapper that runs the product build). |
| `KB` | Kbuild or DKMS (Linux kernel build). |
| `ZE` | Zephyr module (`zephyr/module.yml`, west). |
| `ESP` | ESP-IDF (Espressif). |
| `GEN` | Generated-config (PlatformIO, Arduino, Mynewt, NuttX). |
| `VS` | Visual Studio or MSVC project. |
| `ECO` | Ecosystem or bindings tool (pip, cargo, go, Maven, .NET). |

Status marks:

| Mark | Meaning |
|---|---|
| ✅ | Ships today. The build files exist in-tree now. |
| ▲ | Needs the promoted wolfssl-compliance-tooling front end. |
| ○ | Documented port. Not a first-class in-tree build file. |
| ▢ | Restricted vendor stub. The build files are not public. |
| ✖ | Not applicable. |
| ✔ | Verified in this workspace. |
| ✘ | Not in this checkout. Verify at the source. |

Composition flavor:

| Code | Meaning |
|---|---|
| `LIB` | Record the built library. Input: `--lib`. |
| `SRC` | Record the compiled source set. Input: `--srcs-file`. |
| `DEP` | Record a wrapper package and a declared wolfSSL dependency. Input: `--dep-wolfssl`. |
| `*` | As-built or integrity-locked constraint. Hash the artifact as built. Do not regenerate. Do not substitute a source list. |

The `*` mark is a constraint, not a fourth flavor. It attaches to `LIB` for FIPS
userspace canisters and for kernel modules.

## 3. Axis 1 — config values

| Value | gen-sbom input | Used by |
|---|---|---|
| `options.h` | `--options-h` | wolfSSL library builds. |
| `user_settings.h` | `--user-settings` | embedded, IDE, wolfHSM, wolfSentry, Kits. |
| `config.h` | product-local `--options-h` or `--user-settings` | wolfIP, wolfEngine. |
| kernel `.config` | kbuild makes a header from `autoconf.h`, then `--options-h` | linuxkm, bsdkm, wolfGuard. |

The config is necessary for every row. It is sufficient for none. Pair it with a
composition mechanism.

## 4. Axis 2 — composition mechanisms

| Mechanism | Artifact | gen-sbom input | Rule |
|---|---|---|---|
| `LIB` | `lib*.a` or `lib*.so` | `--lib` | Hash the built library. |
| `SRC` | compiled `.c/.S` set | `--srcs-file` (gitoid) | Enumerate the real sources. |
| `DEP` | wrapper package plus declared dependency | `--dep-wolfssl` and an ecosystem tool | The ecosystem generator owns it. |
| `*` as-built | FIPS canister or `.ko` (plus in-core hash) | `--lib` on the as-built artifact | Hash as-built. Do not substitute sources. |

## 5. Master grid

### 5.1 Reference (R)

| Product | Front ends | Flavor | Config | Evidence |
|---|---|---|---|---|
| wolfSSL — library (autotools) | `A ✅` `ZE ✅` `ESP ✅` `GEN ○` `VS ✅` | `LIB` | options.h / user_settings | ✔ |
| wolfSSL — library (cmake) | `C ✅` | `LIB` | options.h / user_settings | ✔ |
| wolfSSL — `IDE/` (58 trees) | `IAR ▲` `CDB ▲` `RT ▲` | `SRC` | per-tree user_settings | ✔ |
| wolfSSL — FIPS userspace (XCODE-FIPSv2/v5/v6, WIN-SRTP-KDF-140-3) | `IAR ▲` `CDB ▲` | `LIB*` | user_settings | ✔ |
| wolfSSL — kernel (linuxkm + bsdkm) | `M ▲` `CDB ▲` `KB ▲` | `LIB*` (`.ko`) | kernel `.config` → synth header | ✔ |

The `IDE/` count is 58 directories. The 59th entry, `include.am`, is a file, not
a tree.

### 5.2 Libraries (L)

| Product | Front ends | Flavor | Config | Evidence |
|---|---|---|---|---|
| wolfSSH | `A ✅` `C/ZE ✅` `M ○` | `LIB` | wolfssh/options.h | ✔ |
| wolfProvider | `A ✅` (autotools only) | `LIB` (dep wolfSSL + OpenSSL 3) | product-local | ✔ |
| wolfEngine | `A ✅` (autotools only) | `LIB` (dep wolfSSL/OpenSSL) | include/config.h | ✔ |
| wolfCLU | `A ✅` | `LIB` (app; dep wolfSSL) | user_settings (winvs) | ✔ |
| wolfSCEP | `A ✅` (autotools only) | `LIB` (dep wolfSSL) | product-local | ✔ |
| wolfTPM | `A ✅` `C ✅` `ZE ✅` `ESP ✅` | `LIB` | wolftpm user_settings | ✔ |
| wolfMQTT | `A ✅` `C ✅` `ZE ✅` `ESP ✅` `GEN(Arduino) ○` | `LIB` | wolfmqtt/options.h | ✔ |
| wolfPKCS11 | `A ▲` `C ▲` | `LIB` (dep wolfSSL) | user_settings | ✘ not in this tree |
| wolfHSM | `M ✅` (core, host cc); ports `▢` | `SRC` core (+`LIB` posix); ports `SRC`/declared only | wolfhsm/wh_settings.h | ✔ (core=S / tests=E) |

The wolfHSM vendor ports are restricted stubs. They have no public build files.
So you cannot run a compdb or IAR extractor on them. Only `posix` and `skeleton`
are first-class. The ports are `infineon/tc3xx`, `renesas/rh850f1km`,
`stmicro/SR6`, `stmicro/spc58nn`, `microchip/pic32cz`, and `ti/tda4vh`.

### 5.3 Small (S)

| Product | Front ends | Flavor | Config | Evidence |
|---|---|---|---|---|
| wolfSentry | `M ✅` (plain Make only; CMake in one example) | `LIB` | user_settings | ✔ |
| wolfIP | `C ✅` `M ✅` | `LIB`/`SRC` | config.h (stm32h5/rp2350) | ✔ |

### 5.4 Embedded (E)

| Product | Front ends | Flavor | Config | Evidence |
|---|---|---|---|---|
| wolfBoot | `C ✅` `M ✅` `IAR ✅` `CDB ✅` `RT ✅` `ZE ✅` + Pico SDK, VS(keytools) | `SRC` | target `.config` | ✔ — needs the arch.mk path-scrub |

### 5.5 Kernel product (tier unset)

| Product | Front ends | Flavor | Config | Evidence |
|---|---|---|---|---|
| wolfGuard | `KB/DKMS ▲` + `M` (userspace CLI, mingw cross) | `LIB*` (links wolfSSL linuxkm) | kernel `.config` | ✘ not in this tree — needs a tier and an owner |

### 5.6 Bindings (B)

All bindings use the `DEP` flavor and the `ECO` front end.

| Product | Build | Link mechanism → SBOM behavior | Evidence |
|---|---|---|---|
| wolfSSL JNI/JSSE | Ant + Maven + Make | links prebuilt libwolfssl → declared-dep | ✘ |
| wolfCrypt JNI/JCE | same repo | declared-dep | ✘ |
| wolfSSL Python | setuptools + cffi | builds wolfSSL from submodule → two-level SBOM possible (or `USE_LOCAL_WOLFSSL`) | ✘ |
| wolfCrypt Python | setuptools + cffi | links wolfSSL → declared-dep | ✘ |
| wolfCrypt rustls provider | cargo | `-sys` crate (bindgen), out-of-tree → declared-dep | ✘ |
| wolfSSL Go | go modules + cgo | links prebuilt (`-lwolfssl`) → declared-dep | ✘ |
| wolfSSL C# | MSBuild/.NET + native vcxproj | P/Invoke; native built separately → declared-dep | ✔ (`wolfssl/wrapper/CSharp`) |

### 5.7 Features

A feature ships inside wolfSSL. It has no standalone SBOM. It appears as a
component in the wolfSSL SBOM.

| Product | Notes | Evidence |
|---|---|---|
| wolfCrypt | same source tree as wolfSSL | ✔ |
| SSL/TLS Sniffer | ships inside wolfSSL (`sslSniffer.vcxproj`) | ✔ (`wolfssl/sslSniffer`) |
| wolfEntropy | via wolfCrypt (`wolfcrypt/src/wolfentropy.c`) | ✔ |
| wolfFE | to be defined; candidate; do not attest | ✘ |

### 5.8 Kits

A Kit is a customer demo end-product. It uses a two-level composition SBOM.

| Product | Front ends | Flavor | Evidence |
|---|---|---|---|
| CRA Kit (base) | `C`, user_settings | two-level composition | ✔ (`wolfssl-examples`) |
| CRA Kit (cmake + embedded) | `C`, user_settings (+`--srcs-file`) | two-level composition | ✔ |

## 6. SBOM attestation caveats

Obey these caveats when you attest support.

- Do not attest Bazel or Meson. They are absent from wolfSSL 5.9.x.
- TI is not first-class in libwolfSSL. There is no `__TI_*` macro and no CCS
  project. TI is real in wolfBoot (`armcl`) and in the wolfHSM TDA4VH port stub.
- Microchip is 16-bit and 32-bit only (XC32, XC16). There is no 8-bit PIC and no
  SDCC.
- The wolfHSM embedded toolchains (Aurix/HighTec, GHS/CC-RX, SPC5, CCS TI) live
  in restricted vendor stubs. They are not in the public tree.
- The `__clang__` counts are inflated by auto-generated port asm, not by
  Clang-only logic.
- Scrub absolute host paths from captured macros. A path-valued define, for
  example `PICO_SDK_PATH` from `arch.mk`, otherwise breaks byte-reproducibility
  and leaks a local path into a shipped SBOM.

## 7. Evidence caveats about this matrix

- The roster lists 28 products. This workspace holds a subset. These are not in
  this workspace, so verify them at the source: wolfPKCS11, wolfGuard, all
  bindings except C#, and wolfFE.
- The roster version is wolfSSL 5.9.2. This workspace holds `wolfssl` and
  `wolfssl-5.9.1`. Pin the exact tag that the SBOM claims.

## 8. Open decisions

1. Engine home. wolfssl-compliance-tooling is canonical. wolfSSL is one more `wolfssl-compliance-tooling-sync`
   target. wolfSSL keeps its own vendored copy. No product gains a build-time
   dependency on wolfssl-compliance-tooling. This keeps PLAN.md §10 ("no submodule, no network
   pull"). It needs a named owner's sign-off.
2. wolfGuard tier. The tier is unset. Assign a tier and an owner.
3. `share/` layout. The shared CMake fragment must be a function, not a
   per-product target. See PLAN.md §12.

## 9. Dictionary

### 9.1 SBOM and CRA terms

| Term | Meaning |
|---|---|
| SBOM | Software Bill of Materials. A machine-readable inventory of a build. |
| CRA | EU Cyber Resilience Act. The regulation that requires SBOMs. |
| CycloneDX 1.6 | One SBOM format. |
| SPDX 2.3 | One SBOM format. |
| gitoid | Git Object Identifier. A content hash for a source file. |
| two-level composition | An SBOM that nests the end product and its wolfSSL dependency. |
| declared-dep | The SBOM names wolfSSL as a dependency but does not rebuild it. |
| source-inventory | An SBOM that lists sources only, with no build config. |
| path scrub | Remove absolute host paths from captured macros for reproducibility. |
| CSAF | Common Security Advisory Framework 2.0 advisory. |
| VEX | Vulnerability Exploitability eXchange statement. |
| bomsh | The OmniBOR build-trace tool that adds provenance. |

### 9.2 gen-sbom flags

| Flag | Meaning |
|---|---|
| `--options-h` | Path to a flat `#define` header (config source). |
| `--user-settings` | Path to `user_settings.h` (config source). |
| `--lib` | Path to the built library to hash (composition). |
| `--srcs-file` | File that lists compiled sources, one per line (composition). |
| `--dep-wolfssl` | Declare wolfSSL as a dependency (bindings). |
| `--no-artifact-hash` | Do not recompute the artifact hash. For as-built FIPS/kernel output. |
| `--source-only` | Produce a source-inventory SBOM with no build config. |

### 9.3 Build, link, and language terms

| Term | Meaning |
|---|---|
| `arch.mk` | wolfBoot Make file that sets per-architecture CFLAGS, toolchain, and sources. |
| `linuxkm` | wolfSSL Linux kernel module front end. Output: `libwolfssl.ko`. |
| `bsdkm` | wolfSSL BSD kernel module front end. |
| `autoconf.h` | Header that the kernel build makes from `.config`. |
| DKMS | Dynamic Kernel Module Support. Rebuilds a module per kernel. |
| FIPS canister | The certified, integrity-hashed crypto object in a FIPS build. |
| in-core hash | Integrity hash computed at build time and stored inside the module. |
| host `cc` | The build machine's own C compiler, used for macro capture. |
| mingw | Minimalist GNU for Windows. A cross toolchain for Windows. |
| JNI | Java Native Interface. Lets Java call C. |
| JSSE | Java Secure Socket Extension. TLS provider for Java. |
| JCE | Java Cryptography Extension. Crypto provider for Java. |
| cffi | C Foreign Function Interface for Python. |
| cgo | The Go feature that calls C code. |
| `-sys` crate | A Rust crate that links a native C library. |
| bindgen | A tool that makes Rust bindings from C headers. |
| P/Invoke | Platform Invoke. Lets C# call a native DLL. |
| `USE_LOCAL_WOLFSSL` | Python build flag to link a prebuilt wolfSSL. |

### 9.4 Toolchains and IDE codes

| Term | Meaning |
|---|---|
| GHS | Green Hills Software (MULTI compiler). |
| CC-RX | Renesas C compiler for the RX core (`__CCRX__`). |
| armcl | Texas Instruments ARM compiler. |
| CCS | TI Code Composer Studio. |
| SPC5 | STMicro SPC5 automotive MCU toolchain. |
| Aurix / HighTec | Infineon AURIX (TriCore) MCU and its HighTec GCC toolchain. |
| XC32 / XC16 | Microchip 32-bit and 16-bit C compilers. |
| SDCC | Small Device C Compiler (8-bit). Not supported. |
| EWARM | IAR Embedded Workbench for ARM. |
| XCODE-FIPSv2/v5/v6 | Apple Xcode project trees for FIPS validations. |
| WIN-SRTP-KDF-140-3 | Windows FIPS 140-3 SRTP key-derivation validation tree. |
