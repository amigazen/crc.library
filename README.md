# crc.library

crc.library is a shared library for Amiga from **amigazen project**. It provides CRC, checksum, sum, XOR, and message-digest routines for archivers, file managers, and version-control clients — Zip and GZip CRC-32, Arc CRC-16, 32-bit WRAP checksums, PowerPacker passwords, BSD/SYSV `sum`, POSIX `cksum`, MD5, SHA-1, SHA-256, and related variants — without copying table-driven code into every application.

**One-shot** callers pass a buffer and length to a `Do*` function (for example `DoCRC32_2(Mem, Size)`) and read the result from the trap. **Streaming** callers use `CRCNew`, `CRCUpdate`, `CRCFinal`, and `CRCDispose` when data arrives in chunks from disk or a pack file; the streamed result matches the corresponding one-shot call over the same bytes. The public API has **43** LVOs in four groups: archive/filesystem CRCs, sums and POSIX utilities, git/Subversion digests, and streaming plus four reserved slots for future one-shot algorithms.

Algorithm cores are from **Dirk Stoecker's GetCRC** utility (public domain); the Amiga shared-library port follows **Jim Sunrise's crc.library v1.0** (2006). This **2.0** release adds SHA-1/SHA-256, POSIX sums, pooled streaming contexts, and ToolKit build/SDK layout (canonical SFD, NDK 3.2 headers, `CRCTest` with 37 suites). LVOs **1–28** remain binary-compatible with Jim Sunrise's release; new functions are appended only.

## [amigazen project](http://www.amigazen.com)

*A web, suddenly*

*Forty years meditation*

*Minds awaken, free*

**amigazen project** is using modern software development tools and methods to update and rerelease classic Amiga open source software. Projects include a new AWeb, a new Amiga Python 2, and the ToolKit project — a universal SDK for Amiga development. All *amigazen project* releases are guaranteed to build against the ToolKit standard so that anyone can download and begin contributing straightaway without having to tailor the toolchain for their own setup.

This **2.0** release is still Jim Sunrise's library port of Dirk Stoecker's GetCRC algorithms, refactored for NDK 3.2 and ToolKit by amigazen project. The core checksum implementations remain those of GetCRC (public domain); the Amiga library layers (startup, SFD, pool, tests) are redistributed under the BSD 2-Clause License (see [LICENSE.md](LICENSE.md)).

The amigazen project philosophy is based on openness:

*Open* to anyone and everyone — *Open* source and free for all — *Open* your mind and create!

PRs for all projects are gratefully received at [GitHub](https://github.com/amigazen/). While the focus now is on classic 68k software, it is intended that all amigazen project releases can be ported to other Amiga-like systems including AROS and MorphOS where feasible.

## History

The checksum implementations in this tree trace to two earlier projects:

**GetCRC** — portable ANSI-C utility by **Dirk Stoecker** (public domain). Versions 1.0–1.19 (1997–2003) collected CRC-16/32 variants, CHS, sum, EOR, MD5 (1.14), SHA-1 (1.18), and BSD `sum`, SYSV `sum`, and POSIX `cksum` (1.19). Reference source is in `Source/GetCRC/`.

**crc.library v1.0** — **Jim Sunrise** (October 2006) packaged twenty-eight GetCRC algorithms as an AmigaOS 3.x shared library. Public domain; distributed on Aminet. LVOs 1–28 in this tree use the same vector offsets as that release (`md5sum` has been renamed to `DoMD5Sum` in 2.0 at the same offset, with the same function prototype).

**amigazen project** releases (July 2026):

| Version | Maintainer | Notes |
|---------|------------|-------|
| 1.1 | amigazen project | ToolKit build: SFD/NDK headers, engine module split, `CRCTest`, replaced all C library functions with Amiga native equivalents |
| **2.0** | amigazen project | `DoSHA1`/`DoSHA256`, POSIX sums, streaming API, exec memory pool, four reserved LVOs; **43** public functions |

Version 2.0 appends new LVOs - existing binaries built against Jim Sunrise's 1.0 still work with `OpenLibrary("crc.library", 1)`.

See [CHANGELOG.md](CHANGELOG.md) for per-release detail.

## The one-shot and streaming model

crc.library offers two ways to run the same algorithm:

| Model | When to use | API |
|-------|-------------|-----|
| **One-shot** | Buffer already in memory | `DoCRC32_2(Mem, Size)`, `DoSHA1(...)`, etc. |
| **Streaming** | File or pack stream too large to load at once | `CRCNew` → `CRCUpdate` (repeat) → `CRCFinal` → `CRCDispose` |

Streaming uses the same numeric results as one-shot: feed arbitrary chunk sizes and the outcome matches a single call over the concatenated data. Pick the algorithm with a `CRC_*` constant from `<libraries/crc.h>` (33 selectors, one per one-shot function). `CRCDigestLength(type)` tells you whether `CRCFinal` returns a value in **d0** (CRC/checksum) or writes a digest buffer (MD5, SHA-1, SHA-256).

Contexts are carved from a **lazy exec memory pool** in the library base; `CRCNew`/`CRCDispose` are semaphore-protected for multi-task allocation. Once you hold a handle, `CRCUpdate`/`CRCFinal` touch only your context — no locking required.

**What crc.library is not:** a zlib/LhA compressor, a general crypto toolkit, or a handle-based primary API for one-shot callers. Compression CRCs live in your zlib library; new one-shot algorithms land in the four **reserved** LVO slots (`CRCReserved1`…`4`) before the streaming block as the API grows.

## About crc.library

`crc.library` exposes **forty-three public LVOs** (bias 30) in four logical groups:

### Archive and filesystem CRCs (one-shot)

| Function | Typical use |
|----------|-------------|
| `DoCRC32_1` … `DoCRC32_6` | PCompress, Zip/GZip, BZip2, Ace, GPatch, … |
| `DoCRC16_1` … `DoCRC16_4` | Arc, DMS, CCITT/XModem, Zoom, … |
| `DoCHS32_1M` / `DoCHS32_1I` | 32-bit WRAP checksum (Motorola / Intel) |
| `DoCHS32_2` | 32-bit block checksum (0x1600-byte blocks) |
| `DoCHS16_1` | PowerPacker passwords |

### Sums, EOR, and POSIX utilities (one-shot)

| Function | Typical use |
|----------|-------------|
| `DoEORB`, `DoEORWM`/`WI`, `DoEORLM`/`LI` | XOR reduction |
| `DoSumSB` … `DoSumLI` | Signed/unsigned byte, word, long sums |
| `DoCHS16_2`, `DoCHS16_3` | BSD `sum`, SYSV `sum` |
| `DoCRC32_7` | POSIX `cksum` |

### Message digests — git / Subversion (one-shot)

| Function | Typical use |
|----------|-------------|
| `DoMD5Sum` | Subversion deltas, legacy tooling (`md5sum` macro for source compat) |
| `DoSHA1` | Git object hashing |
| `DoSHA256` | SHA-256 git repositories |

### Streaming and reserved (v2.0)

| Function | Role |
|----------|------|
| `CRCReserved1` … `CRCReserved4` | Placeholders for future one-shot algorithms (return zero; do not call) |
| `CRCNew` | Allocate a streaming context from the library pool |
| `CRCReset` | Re-init a context for reuse |
| `CRCUpdate` | Feed a data block |
| `CRCFinal` | Finish; numeric result or digest |
| `CRCDispose` | Return context to the pool |
| `CRCDigestLength` | Query digest size (0 = numeric algorithm) |

### Lineage compatibility

| Line | Version | Relationship to this tree |
|------|---------|----------------------------|
| **GetCRC utility** | 1.19 | Algorithm source (PD); see `Source/GetCRC/` |
| **Jim Sunrise library** | 1.0 | **LVOs 1–28** — binary compatible (same offsets) |
| **amigazen ToolKit** | 2.0 | **Target ABI** — this release |


```

## Build (Amiga ToolKit)

From `Source/`:

```text
smake all
smake install      # copies crc.library to LIBS:
smake unittests    # builds Source/unittests/CRCTest
```

Client code: `#include <proto/crc.h>`, define `struct Library *CRCBase;` in one
`.c` file, `OpenLibrary("crc.library", 2)` (version **1** still works).

Example streaming hash:

```c
APTR h = CRCNew(CRC_SHA256);
while ((len = Read(fh, buf, sizeof buf)) > 0)
    CRCUpdate(h, buf, len);
CRCFinal(h, digest);
CRCDispose(h);
```

## Contact

- At GitHub https://github.com/amigazen/crc/
- On the web at http://www.amigazen.com/toolkit/ (Amiga browser compatible)
- Or email toolkit@amigazen.com

## Acknowledgements

**GetCRC** was written by **Dirk Stoecker** (public domain checksum portions). **crc.library v1.0** was ported by **Jim Sunrise** (2006, public domain). This **2.0** ToolKit release is by the **amigazen project** (2026). SHA-1/SHA-256 engine cores adapt Brad Conte's public-domain implementations. See [LICENSE.md](LICENSE.md) for copyright and redistribution terms.

*Amiga* is a trademark of **Amiga Inc**.
