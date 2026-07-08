#ifndef CRC_PRIVATE_CRC_INTERNAL_H
#define CRC_PRIVATE_CRC_INTERNAL_H

/*
 * Engine entry points — not exported LVOs; called from crc_lvos.c.
 */

#include <exec/types.h>
#include <exec/libraries.h>
#include <exec/semaphores.h>
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

/*
 * Extended library base: the plain struct Library is followed by an exec
 * memory pool used for streaming contexts, arbitrated by a semaphore.  The
 * pool is created lazily on the first CRCNew() call.
 */
struct CRCLibBase
{
	struct Library cb_Lib;
	APTR cb_Pool;
	struct SignalSemaphore cb_PoolSem;
};

/*
 * Streaming context.  Allocated from the library pool by CRCNew().  A
 * type-specific tail follows the header in the same allocation: nothing for
 * the plain CRC/checksum types, a digest sub-context for the hash types, or a
 * block buffer for the block-structured DoCHS32_2 checksum.
 */
struct CRCHandle
{
	ULONG ch_Size;		/* total allocation size (for FreePooled)  */
	ULONG ch_Type;		/* CRC_* selector                          */
	ULONG ch_Value;		/* running CRC / checksum accumulator       */
	ULONG ch_Length;	/* total bytes consumed                     */
	UBYTE ch_Part[4];	/* partial word/long assembly buffer        */
	UWORD ch_PartLen;	/* bytes buffered (also block fill for LFS) */
	UWORD ch_Pad;
};

/* Opaque digest sub-context helpers (state lives in the handle tail). */
ULONG crc_md5_ctxsize(void);
void crc_md5_init(APTR ctx);
void crc_md5_update(APTR ctx, const UBYTE *data, ULONG len);
void crc_md5_final(APTR ctx, UBYTE *digest);

ULONG crc_sha1_ctxsize(void);
void crc_sha1_init(APTR ctx);
void crc_sha1_update(APTR ctx, const UBYTE *data, ULONG len);
void crc_sha1_final(APTR ctx, UBYTE *digest);

ULONG crc_sha256_ctxsize(void);
void crc_sha256_init(APTR ctx);
void crc_sha256_update(APTR ctx, const UBYTE *data, ULONG len);
void crc_sha256_final(APTR ctx, UBYTE *digest);

/* Streaming engine (state kept in the handle; no library globals touched). */
ULONG crc_stream_tailsize(ULONG type);
ULONG crc_stream_digestlen(ULONG type);
void crc_stream_init(struct CRCHandle *h);
void crc_stream_update(struct CRCHandle *h, const UBYTE *Mem, LONG Size);
ULONG crc_stream_final(struct CRCHandle *h, UBYTE *Digest);

/* Pooled handle management (implemented in crc_stream.c). */
struct CRCHandle *crc_CRCNew(ULONG type);
void crc_CRCReset(struct CRCHandle *h);
void crc_CRCUpdate(struct CRCHandle *h, const UBYTE *Mem, LONG Size);
ULONG crc_CRCFinal(struct CRCHandle *h, UBYTE *Digest);
void crc_CRCDispose(struct CRCHandle *h);
ULONG crc_CRCDigestLength(ULONG type);

#endif /* CRC_PRIVATE_CRC_INTERNAL_H */
