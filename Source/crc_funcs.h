/*
 * crc_funcs.h - LVO declarations for crc.library sources
 *
 * Register layout matches SDK/SFD/crc_lib.sfd and FuncTab[] in StartUp.c.
 */

#ifndef CRC_FUNCS_H
#define CRC_FUNCS_H

#include <exec/types.h>
#include <clib/compiler-specific.h>
#include <libraries/crc.h>

struct Library *__ASM__ __SAVE_DS__ LibInit(
	__REG__(a6, struct ExecBase *sysbase),
	__REG__(a0, APTR seglist),
	__REG__(d0, struct Library *base));
struct Library *__ASM__ __SAVE_DS__ LibOpen(
	__REG__(a6, struct Library *base));
APTR __ASM__ __SAVE_DS__ LibClose(
	__REG__(a6, struct Library *base));
APTR __ASM__ __SAVE_DS__ LibExpunge(
	__REG__(a6, struct Library *base));
LONG __ASM__ LibReserved(void);

ULONG __ASM__ __SAVE_DS__ DoCRC32_1(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size));
ULONG __ASM__ __SAVE_DS__ DoCRC32_2(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size));
ULONG __ASM__ __SAVE_DS__ DoCRC32_3(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size));
ULONG __ASM__ __SAVE_DS__ DoCRC32_4(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size));
ULONG __ASM__ __SAVE_DS__ DoCRC32_5(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size));
ULONG __ASM__ __SAVE_DS__ DoCRC32_6(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size));
UWORD __ASM__ __SAVE_DS__ DoCRC16_1(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size));
UWORD __ASM__ __SAVE_DS__ DoCRC16_2(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size));
UWORD __ASM__ __SAVE_DS__ DoCRC16_3(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size));
UWORD __ASM__ __SAVE_DS__ DoCRC16_4(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size));
ULONG __ASM__ __SAVE_DS__ DoCHS32_1M(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size));
ULONG __ASM__ __SAVE_DS__ DoCHS32_1I(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size));
ULONG __ASM__ __SAVE_DS__ DoCHS32_2(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size));
UWORD __ASM__ __SAVE_DS__ DoCHS16_1(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size));
UBYTE __ASM__ __SAVE_DS__ DoEORB(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size));
UWORD __ASM__ __SAVE_DS__ DoEORWM(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size));
UWORD __ASM__ __SAVE_DS__ DoEORWI(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size));
ULONG __ASM__ __SAVE_DS__ DoEORLM(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size));
ULONG __ASM__ __SAVE_DS__ DoEORLI(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size));
ULONG __ASM__ __SAVE_DS__ DoSumSB(
	__REG__(a0, const BYTE *Mem),
	__REG__(d0, LONG Size));
ULONG __ASM__ __SAVE_DS__ DoSumSWM(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size));
ULONG __ASM__ __SAVE_DS__ DoSumSWI(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size));
ULONG __ASM__ __SAVE_DS__ DoSumUB(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size));
ULONG __ASM__ __SAVE_DS__ DoSumUWM(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size));
ULONG __ASM__ __SAVE_DS__ DoSumUWI(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size));
ULONG __ASM__ __SAVE_DS__ DoSumLM(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size));
ULONG __ASM__ __SAVE_DS__ DoSumLI(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size));
VOID __ASM__ __SAVE_DS__ DoMD5Sum(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size),
	__REG__(a1, UBYTE *Digest));
VOID __ASM__ __SAVE_DS__ DoSHA1(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size),
	__REG__(a1, UBYTE *Digest));
VOID __ASM__ __SAVE_DS__ DoSHA256(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size),
	__REG__(a1, UBYTE *Digest));
UWORD __ASM__ __SAVE_DS__ DoCHS16_2(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size));
UWORD __ASM__ __SAVE_DS__ DoCHS16_3(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size));
ULONG __ASM__ __SAVE_DS__ DoCRC32_7(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size));

#endif /* CRC_FUNCS_H */
