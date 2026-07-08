/*
 * crc_stream.c - pooled streaming-context management for crc.library
 *
 * Contexts are carved from a single exec memory pool held in the library base
 * and created lazily on first use.  Pool allocation and freeing are arbitrated
 * by a semaphore so that CRCNew()/CRCDispose() are safe to call from several
 * tasks at once.  Once a caller owns a handle, CRCUpdate()/CRCFinal() touch
 * only that handle and need no locking.
 */

#include <exec/types.h>
#include <exec/memory.h>

#include <proto/exec.h>

#include "private/crc_internal.h"

extern struct Library *CRCBase;
extern struct ExecBase *SysBase;

#define CRC_POOL_PUDDLE 4096
#define CRC_POOL_THRESH 2048

struct CRCHandle *
crc_CRCNew(ULONG type)
{
	struct CRCLibBase *base = (struct CRCLibBase *)CRCBase;
	struct CRCHandle *h = NULL;
	ULONG size;

	if (type >= CRC_TYPE_COUNT)
		return NULL;

	size = (ULONG)sizeof(struct CRCHandle) + crc_stream_tailsize(type);

	ObtainSemaphore(&base->cb_PoolSem);
	if (base->cb_Pool == NULL)
		base->cb_Pool = CreatePool(MEMF_ANY | MEMF_CLEAR,
			CRC_POOL_PUDDLE, CRC_POOL_THRESH);
	if (base->cb_Pool != NULL)
		h = (struct CRCHandle *)AllocPooled(base->cb_Pool, size);
	ReleaseSemaphore(&base->cb_PoolSem);

	if (h == NULL)
		return NULL;

	h->ch_Size = size;
	h->ch_Type = type;
	crc_stream_init(h);

	return h;
}

void
crc_CRCReset(struct CRCHandle *h)
{
	if (h != NULL)
		crc_stream_init(h);
}

void
crc_CRCUpdate(struct CRCHandle *h, const UBYTE *Mem, LONG Size)
{
	if (h != NULL && Mem != NULL && Size > 0)
		crc_stream_update(h, Mem, Size);
}

ULONG
crc_CRCFinal(struct CRCHandle *h, UBYTE *Digest)
{
	if (h == NULL)
		return 0;

	return crc_stream_final(h, Digest);
}

void
crc_CRCDispose(struct CRCHandle *h)
{
	struct CRCLibBase *base = (struct CRCLibBase *)CRCBase;

	if (h == NULL)
		return;

	ObtainSemaphore(&base->cb_PoolSem);
	if (base->cb_Pool != NULL)
		FreePooled(base->cb_Pool, h, h->ch_Size);
	ReleaseSemaphore(&base->cb_PoolSem);
}

ULONG
crc_CRCDigestLength(ULONG type)
{
	if (type >= CRC_TYPE_COUNT)
		return 0;

	return crc_stream_digestlen(type);
}
