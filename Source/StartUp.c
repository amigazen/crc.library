/*
 * StartUp.c - LVO trap, function table, and LibInit / LibOpen / LibClose /
 *             LibExpunge / LibReserved for crc.library
 *
 * FuncTab[] order MUST match SDK/SFD/crc_lib.sfd.
 */

#include <exec/types.h>
#include <exec/libraries.h>
#include <exec/resident.h>
#include <exec/memory.h>

#include <proto/exec.h>

#include "private/crc_build.h"
#include "private/crc_internal.h"
#include "crc_funcs.h"

extern const char AS_LibName[];
extern const char AS_LibId[];

struct Library *CRCBase;
struct ExecBase *SysBase;
APTR SegList;

struct InitTable {
	ULONG it_LibSize;
	APTR *it_FuncTable;
	APTR it_DataTable;
	APTR it_InitFunc;
};

static VOID FreeLib(struct Library *lib);

APTR FuncTab[];

struct InitTable InitTab = {
	(ULONG)sizeof(struct CRCLibBase),
	(APTR *)FuncTab,
	(APTR)NULL,
	(APTR)LibInit
};

APTR FuncTab[] = {
	(APTR)LibOpen,
	(APTR)LibClose,
	(APTR)LibExpunge,
	(APTR)LibReserved,
	(APTR)DoCRC32_1,
	(APTR)DoCRC32_2,
	(APTR)DoCRC32_3,
	(APTR)DoCRC32_4,
	(APTR)DoCRC32_5,
	(APTR)DoCRC32_6,
	(APTR)DoCRC16_1,
	(APTR)DoCRC16_2,
	(APTR)DoCRC16_3,
	(APTR)DoCRC16_4,
	(APTR)DoCHS32_1M,
	(APTR)DoCHS32_1I,
	(APTR)DoCHS32_2,
	(APTR)DoCHS16_1,
	(APTR)DoEORB,
	(APTR)DoEORWM,
	(APTR)DoEORWI,
	(APTR)DoEORLM,
	(APTR)DoEORLI,
	(APTR)DoSumSB,
	(APTR)DoSumSWM,
	(APTR)DoSumSWI,
	(APTR)DoSumUB,
	(APTR)DoSumUWM,
	(APTR)DoSumUWI,
	(APTR)DoSumLM,
	(APTR)DoSumLI,
	(APTR)DoMD5Sum,
	(APTR)DoSHA1,
	(APTR)DoSHA256,
	(APTR)DoCHS16_2,
	(APTR)DoCHS16_3,
	(APTR)DoCRC32_7,
	(APTR)CRCReserved1,
	(APTR)CRCReserved2,
	(APTR)CRCReserved3,
	(APTR)CRCReserved4,
	(APTR)CRCNew,
	(APTR)CRCReset,
	(APTR)CRCUpdate,
	(APTR)CRCFinal,
	(APTR)CRCDispose,
	(APTR)CRCDigestLength,
	(APTR)((LONG)-1)
};

LONG
__ASM__ LibReserved(void)
{
	return 0;
}

struct Library *
__ASM__ __SAVE_DS__ LibInit(
	__REG__(a6, struct ExecBase *sysbase),
	__REG__(a0, APTR seglist),
	__REG__(d0, struct Library *lib))
{
	struct CRCLibBase *cb = (struct CRCLibBase *)lib;

	SysBase = sysbase;
	SegList = seglist;
	CRCBase = lib;

	cb->cb_Pool = NULL;
	InitSemaphore(&cb->cb_PoolSem);

	lib->lib_Node.ln_Type = NT_LIBRARY;
	lib->lib_Node.ln_Pri = 0;
	lib->lib_Node.ln_Name = (STRPTR)AS_LibName;
	lib->lib_Flags = LIBF_CHANGED | LIBF_SUMUSED;
	lib->lib_Version = CRC_LIB_VERSION;
	lib->lib_Revision = CRC_LIB_REVISION;
	lib->lib_IdString = (STRPTR)AS_LibId;

	return lib;
}

struct Library *
__ASM__ __SAVE_DS__ LibOpen(__REG__(a6, struct Library *lib))
{
	++lib->lib_OpenCnt;
	lib->lib_Flags &= ~LIBF_DELEXP;
	return lib;
}

APTR
__ASM__ __SAVE_DS__ LibClose(__REG__(a6, struct Library *lib))
{
	if (lib->lib_OpenCnt && --lib->lib_OpenCnt)
	{
		return NULL;
	}

	if (lib->lib_Flags & LIBF_DELEXP)
	{
		return LibExpunge(lib);
	}

	return NULL;
}

APTR
__ASM__ __SAVE_DS__ LibExpunge(__REG__(a6, struct Library *lib))
{
	if (lib->lib_OpenCnt)
	{
		lib->lib_Flags |= LIBF_DELEXP;
		return NULL;
	}

	Remove(&lib->lib_Node);
	FreeLib(lib);

	return SegList;
}

static VOID
FreeLib(struct Library *lib)
{
	struct CRCLibBase *cb = (struct CRCLibBase *)lib;

	if (cb->cb_Pool != NULL)
	{
		DeletePool(cb->cb_Pool);
		cb->cb_Pool = NULL;
	}

	FreeMem((UBYTE *)lib - lib->lib_NegSize, lib->lib_NegSize + lib->lib_PosSize);
	CRCBase = NULL;
}
