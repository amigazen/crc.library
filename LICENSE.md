# BSD 2-Clause License

Copyright (c) 2026 amigazen project  
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Acknowledgements

This repository combines checksum algorithms and Amiga library code from
several authors. The **amigazen project** ToolKit release (2026) is under
**BSD 2-Clause** (above). Earlier layers were placed in the **public domain**
by their authors.

## Dirk Stöcker — GetCRC

**Dirk Stöcker** (SDI) wrote **GetCRC**, a portable collection of CRC,
checksum, EOR, sum, and MD5 routines. The archive readmes and program header
describe the checksum portions (without the later MD4 module) as **public
domain**, usable in other software without restriction. Stöcker's own readme
states: *"Use this tool as you want, but WITHOUT ANY WARRANTY!"*

The algorithm core in this tree (`Source/crc_engine.c`, and the reference
copies under `Source/GetCRC/` and `Source/lib_source/`) derives from
**GetCRC 1.16** (PD) and later GetCRC releases on Aminet.

Contact (from the original archive): `stoecker@epost.de` — see
`Source/GetCRC/GetCRC.readme`.

## Jim Sunrise — crc.library

**Jim Sunrise** ported GetCRC into **crc.library** v1.0 (October 2006), a
shared library exposing 28 checksum LVOs. The Aminet readme
(`crc_library.readme`) lists the release as **public domain**, source
included.

The original monolithic SAS/C build is preserved under `Source/lib_source/`
for reference.

## amigazen project — ToolKit modernisation

The following are under **BSD 2-Clause** (this file):

- SFD-based SDK layout (`SDK/SFD/`, generated headers, LVO equates)
- Split library startup (`Source/StartUp.c`, `Source/LibInit.c`)
- LVO wrappers (`Source/crc_lvos.c`, `Source/crc_funcs.h`)
- Native Amiga helpers (`Source/crc_libc.c`)
- Build system, unit tests, autodocs, and documentation added or rewritten
  for the ToolKit workflow (crc.library v1.1, 2026)

Redistribution of this **combined work** should credit the original authors
above and comply with the BSD 2-Clause terms for the amigazen additions.

---
