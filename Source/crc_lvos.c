/*
 * crc_lvos.c - LVO entry points for crc.library
 */

#include <clib/compiler-specific.h>
#include "crc_funcs.h"
#include "private/crc_internal.h"

__ASM__ __SAVE_DS__ ULONG
DoCRC32_1(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size))
{
	return crc_DoCRC32_1(Mem, Size);
}

__ASM__ __SAVE_DS__ ULONG
DoCRC32_2(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size))
{
	return crc_DoCRC32_2(Mem, Size);
}

__ASM__ __SAVE_DS__ ULONG
DoCRC32_3(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size))
{
	return crc_DoCRC32_3(Mem, Size);
}

__ASM__ __SAVE_DS__ ULONG
DoCRC32_4(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size))
{
	return crc_DoCRC32_4(Mem, Size);
}

__ASM__ __SAVE_DS__ ULONG
DoCRC32_5(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size))
{
	return crc_DoCRC32_5(Mem, Size);
}

__ASM__ __SAVE_DS__ ULONG
DoCRC32_6(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size))
{
	return crc_DoCRC32_6(Mem, Size);
}

__ASM__ __SAVE_DS__ UWORD
DoCRC16_1(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size))
{
	return crc_DoCRC16_1(Mem, Size);
}

__ASM__ __SAVE_DS__ UWORD
DoCRC16_2(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size))
{
	return crc_DoCRC16_2(Mem, Size);
}

__ASM__ __SAVE_DS__ UWORD
DoCRC16_3(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size))
{
	return crc_DoCRC16_3(Mem, Size);
}

__ASM__ __SAVE_DS__ UWORD
DoCRC16_4(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size))
{
	return crc_DoCRC16_4(Mem, Size);
}

__ASM__ __SAVE_DS__ ULONG
DoCHS32_1M(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size))
{
	return crc_DoCHS32_1M(Mem, Size);
}

__ASM__ __SAVE_DS__ ULONG
DoCHS32_1I(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size))
{
	return crc_DoCHS32_1I(Mem, Size);
}

__ASM__ __SAVE_DS__ ULONG
DoCHS32_2(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size))
{
	return crc_DoCHS32_2(Mem, Size);
}

__ASM__ __SAVE_DS__ UWORD
DoCHS16_1(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size))
{
	return crc_DoCHS16_1(Mem, Size);
}

__ASM__ __SAVE_DS__ UBYTE
DoEORB(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size))
{
	return crc_DoEORB(Mem, Size);
}

__ASM__ __SAVE_DS__ UWORD
DoEORWM(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size))
{
	return crc_DoEORWM(Mem, Size);
}

__ASM__ __SAVE_DS__ UWORD
DoEORWI(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size))
{
	return crc_DoEORWI(Mem, Size);
}

__ASM__ __SAVE_DS__ ULONG
DoEORLM(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size))
{
	return crc_DoEORLM(Mem, Size);
}

__ASM__ __SAVE_DS__ ULONG
DoEORLI(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size))
{
	return crc_DoEORLI(Mem, Size);
}

__ASM__ __SAVE_DS__ ULONG
DoSumSB(
	__REG__(a0, const BYTE *Mem),
	__REG__(d0, LONG Size))
{
	return crc_DoSumSB(Mem, Size);
}

__ASM__ __SAVE_DS__ ULONG
DoSumSWM(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size))
{
	return crc_DoSumSWM(Mem, Size);
}

__ASM__ __SAVE_DS__ ULONG
DoSumSWI(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size))
{
	return crc_DoSumSWI(Mem, Size);
}

__ASM__ __SAVE_DS__ ULONG
DoSumUB(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size))
{
	return crc_DoSumUB(Mem, Size);
}

__ASM__ __SAVE_DS__ ULONG
DoSumUWM(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size))
{
	return crc_DoSumUWM(Mem, Size);
}

__ASM__ __SAVE_DS__ ULONG
DoSumUWI(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size))
{
	return crc_DoSumUWI(Mem, Size);
}

__ASM__ __SAVE_DS__ ULONG
DoSumLM(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size))
{
	return crc_DoSumLM(Mem, Size);
}

__ASM__ __SAVE_DS__ ULONG
DoSumLI(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size))
{
	return crc_DoSumLI(Mem, Size);
}

__ASM__ __SAVE_DS__ VOID
DoMD5Sum(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size),
	__REG__(a1, UBYTE *Digest))
{
	crc_DoMD5Sum(Mem, Size, Digest);
}

__ASM__ __SAVE_DS__ VOID
DoSHA1(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size),
	__REG__(a1, UBYTE *Digest))
{
	crc_DoSHA1(Mem, Size, Digest);
}

__ASM__ __SAVE_DS__ VOID
DoSHA256(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size),
	__REG__(a1, UBYTE *Digest))
{
	crc_DoSHA256(Mem, Size, Digest);
}

__ASM__ __SAVE_DS__ UWORD
DoCHS16_2(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size))
{
	return crc_DoCHS16_2(Mem, Size);
}

__ASM__ __SAVE_DS__ UWORD
DoCHS16_3(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size))
{
	return crc_DoCHS16_3(Mem, Size);
}

__ASM__ __SAVE_DS__ ULONG
DoCRC32_7(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size))
{
	return crc_DoCRC32_7(Mem, Size);
}

/* Reserved LVO slots for future one-shot algorithms (v2.0). */

__ASM__ __SAVE_DS__ ULONG
CRCReserved1(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size))
{
	return 0;
}

__ASM__ __SAVE_DS__ ULONG
CRCReserved2(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size))
{
	return 0;
}

__ASM__ __SAVE_DS__ ULONG
CRCReserved3(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size))
{
	return 0;
}

__ASM__ __SAVE_DS__ ULONG
CRCReserved4(
	__REG__(a0, const UBYTE *Mem),
	__REG__(d0, LONG Size))
{
	return 0;
}

/* Incremental (streaming) API */

__ASM__ __SAVE_DS__ APTR
CRCNew(
	__REG__(d0, ULONG type))
{
	return (APTR)crc_CRCNew(type);
}

__ASM__ __SAVE_DS__ VOID
CRCReset(
	__REG__(a0, APTR handle))
{
	crc_CRCReset((struct CRCHandle *)handle);
}

__ASM__ __SAVE_DS__ VOID
CRCUpdate(
	__REG__(a0, APTR handle),
	__REG__(a1, const UBYTE *Mem),
	__REG__(d0, LONG Size))
{
	crc_CRCUpdate((struct CRCHandle *)handle, Mem, Size);
}

__ASM__ __SAVE_DS__ ULONG
CRCFinal(
	__REG__(a0, APTR handle),
	__REG__(a1, UBYTE *Digest))
{
	return crc_CRCFinal((struct CRCHandle *)handle, Digest);
}

__ASM__ __SAVE_DS__ VOID
CRCDispose(
	__REG__(a0, APTR handle))
{
	crc_CRCDispose((struct CRCHandle *)handle);
}

__ASM__ __SAVE_DS__ ULONG
CRCDigestLength(
	__REG__(d0, ULONG type))
{
	return crc_CRCDigestLength(type);
}
