#ifndef CRC_PRIVATE_CRC_INTERNAL_H
#define CRC_PRIVATE_CRC_INTERNAL_H

/*
 * Engine entry points — not exported LVOs; called from crc_lvos.c.
 */

#include <exec/types.h>
#include <libraries/crc.h>

/* Native zero-fill helper (no sc.lib memset) — implemented in crc_libc.c. */
void crc_bzero(void *dest, ULONG n);

ULONG crc_DoCRC32_1(const UBYTE *Mem, LONG Size);
ULONG crc_DoCRC32_2(const UBYTE *Mem, LONG Size);
ULONG crc_DoCRC32_3(const UBYTE *Mem, LONG Size);
ULONG crc_DoCRC32_4(const UBYTE *Mem, LONG Size);
ULONG crc_DoCRC32_5(const UBYTE *Mem, LONG Size);
ULONG crc_DoCRC32_6(const UBYTE *Mem, LONG Size);
UWORD crc_DoCRC16_1(const UBYTE *Mem, LONG Size);
UWORD crc_DoCRC16_2(const UBYTE *Mem, LONG Size);
UWORD crc_DoCRC16_3(const UBYTE *Mem, LONG Size);
UWORD crc_DoCRC16_4(const UBYTE *Mem, LONG Size);
ULONG crc_DoCHS32_1M(const UBYTE *Mem, LONG Size);
ULONG crc_DoCHS32_1I(const UBYTE *Mem, LONG Size);
ULONG crc_DoCHS32_2(const UBYTE *Mem, LONG Size);
UWORD crc_DoCHS16_1(const UBYTE *Mem, LONG Size);
UBYTE crc_DoEORB(const UBYTE *Mem, LONG Size);
UWORD crc_DoEORWM(const UBYTE *Mem, LONG Size);
UWORD crc_DoEORWI(const UBYTE *Mem, LONG Size);
ULONG crc_DoEORLM(const UBYTE *Mem, LONG Size);
ULONG crc_DoEORLI(const UBYTE *Mem, LONG Size);
ULONG crc_DoSumSB(const BYTE *Mem, LONG Size);
ULONG crc_DoSumSWM(const UBYTE *Mem, LONG Size);
ULONG crc_DoSumSWI(const UBYTE *Mem, LONG Size);
ULONG crc_DoSumUB(const UBYTE *Mem, LONG Size);
ULONG crc_DoSumUWM(const UBYTE *Mem, LONG Size);
ULONG crc_DoSumUWI(const UBYTE *Mem, LONG Size);
ULONG crc_DoSumLM(const UBYTE *Mem, LONG Size);
ULONG crc_DoSumLI(const UBYTE *Mem, LONG Size);
void crc_DoMD5Sum(const UBYTE *Mem, LONG Size, UBYTE Digest[SIZEOF_MD5SUM]);
void crc_DoSHA1(const UBYTE *Mem, LONG Size, UBYTE Digest[SIZEOF_SHA1SUM]);
void crc_DoSHA256(const UBYTE *Mem, LONG Size, UBYTE Digest[SIZEOF_SHA256SUM]);
UWORD crc_DoCHS16_2(const UBYTE *Mem, LONG Size);
UWORD crc_DoCHS16_3(const UBYTE *Mem, LONG Size);
ULONG crc_DoCRC32_7(const UBYTE *Mem, LONG Size);

#endif /* CRC_PRIVATE_CRC_INTERNAL_H */
