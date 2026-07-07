/*
 * LibInit.c - ROMTag and version strings for crc.library
 */

#include <exec/types.h>
#include <exec/libraries.h>
#include <exec/resident.h>
#include <clib/compiler-specific.h>

#include "private/crc_build.h"
#include "Rev.h"

const char AS_LibName[] = "crc.library";
const char AS_LibId[] = "crc.library " VERSION " (" DATE ")\r\n";
struct InitTable;
extern struct InitTable InitTab;
extern APTR __ASM__ __SAVE_DS__ LibExpunge(__REG__(a6, struct Library *base));

struct Resident RomTag = {
	RTC_MATCHWORD,
	&RomTag,
	LibExpunge,
	RTF_AUTOINIT,
	VERNUM,
	NT_LIBRARY,
	0,
	(APTR)AS_LibName,
	(APTR)AS_LibId,
	(APTR)&InitTab
};

#ifdef __SASC
void __regargs __chkabort(void) { }
void __regargs _CXBRK(void)     { }
#endif
