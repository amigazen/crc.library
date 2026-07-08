# Changelog

## 2.0 (2026-07-07)

- **Version 2.0** — append-only LVO extension (**43** public functions, bias 30);
  open with `OpenLibrary("crc.library", 2)` 
- **Binary compatibility:** LVOs 1–28 unchanged from crc.library v1.0 / v1.1;
  `DoMD5Sum` remains at offset **−192** (renamed from `md5sum`, same trap layout)
- Rename **`md5sum` → `DoMD5Sum`**; legacy name available as a macro in
  `libraries/crc.h`
- **Message digests** (git / Subversion):
  - `DoSHA1` — object hashing (FIPS 180-1 / RFC 3174)
  - `DoSHA256` — SHA-256 repositories (FIPS 180-4)
- **POSIX / Unix checksums** from GetCRC 1.19 (PD):
  - `DoCHS16_2` — BSD `sum`
  - `DoCHS16_3` — SYSV `sum`
  - `DoCRC32_7` — POSIX `cksum` CRC
- **Reserved LVO slots** — `CRCReserved1`…`CRCReserved4` before the streaming
  block for future one-shot algorithms (e.g. CRC-32C); return zero, do not call
- **Incremental (streaming) API** for data larger than available RAM (git/SVN
  pack files, archive verification):
  - `CRCNew`, `CRCReset`, `CRCUpdate`, `CRCFinal`, `CRCDispose`,
    `CRCDigestLength`
  - All **33** `CRC_*` selectors in `libraries/crc.h`; streamed output is
    bit-identical to the matching one-shot `Do*` call
  - Lazy **exec memory pool** in extended library base (`struct CRCLibBase`);
    semaphore-protected `CRCNew`/`CRCDispose`; per-handle updates need no locking
- Engine split: `crc_sha1.c`, `crc_sha256.c`, `crc_stream.c`; streaming step
  logic in `crc_engine.c`; static CRC tables (no per-call table rebuild)
- **CRCTest** expanded to **37** suites (one-shot vectors, streaming
  equivalence, `CRCDigestLength`, SHA-256 with `CRCReset`)
- Autodocs (`SDK/Autodocs/crc.doc`) for all public LVOs including streaming
  and reserved slots
- SFD, NDK headers, LVO equates, pragmas, and `Source/include` mirror updated

## 1.1 (2026-07-07)

- Modernise to amigazen SFD/ToolKit layout (`SDK/SFD/crc_lib.sfd` canonical API)
- Split legacy monolithic `crc.c` into `StartUp.c`, `LibInit.c`, `crc_engine.c`,
  `crc_lvos.c`, `crc_libc.c`
- Replace `sc.lib` `memset` with native `crc_bzero` / `CopyMem` from `exec.library`
- NDK 3.2-style headers in `SDK/Include_h/`; build mirror in `Source/include/`
- `smakefile` build; **CRCTest** baseline unit tests (28 one-shot LVOs)
- **Binary compatible** with crc.library v1.0 (same 28 public LVOs and offsets)

## 1.0 (2006-10)

- First public release by **Jim Sunrise** (shared-library port of GetCRC 1.16)
- 28 public LVOs: CRC-16/32 variants, CHS, EOR, sums, `md5sum`
- Public domain; distributed on Aminet
