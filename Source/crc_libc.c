/*
 * crc_libc.c - native helpers for crc_engine.c (see LIBC_TO_AMIGA.md)
 *
 * The library must not pull memset/bzero from sc.lib.  AmigaOS 3.x has no
 * exec SetMem, so zero-fill is a CPU longword store loop with a byte tail
 * (the AROS memset strategy).  Copies use exec.library CopyMem directly in
 * crc_engine.c.
 */

#include <exec/types.h>
#include "private/crc_internal.h"

void
crc_bzero(void *dest, ULONG n)
{
	UBYTE *bp;
	ULONG *lp;
	ULONG longs;
	ULONG tail;
	ULONG i;

	bp = (UBYTE *)dest;

	/* Align to a longword boundary with a leading byte fill. */
	while (n != 0 && (((ULONG)bp) & 3) != 0)
	{
		*bp++ = 0;
		--n;
	}

	longs = n >> 2;
	tail = n & 3;

	lp = (ULONG *)bp;
	for (i = 0; i < longs; i++)
	{
		*lp++ = 0;
	}

	bp = (UBYTE *)lp;
	for (i = 0; i < tail; i++)
	{
		*bp++ = 0;
	}
}
