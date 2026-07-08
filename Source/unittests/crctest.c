/*
 * CRCTest - baseline unit tests for crc.library
 *
 * One suite per public LVO. Block/word/long algorithms are exercised with a
 * 4-byte vector (length 4 keeps >>1 and >>2 paths whole and avoids the
 * DoCHS32_2 shift-by-32 edge case); digests use the standard "abc" vectors.
 *
 * Expected values were derived from the engine algorithms in crc_engine.c.
 */

#include <exec/types.h>
#include <dos/dos.h>
#include <libraries/crc.h>

#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/crc.h>

#include <stdio.h>

#include "Rev.h"

struct Library *CRCBase;

/* 0x12 0x34 0x56 0x78 */
static const UBYTE test_vec[] = { 0x12, 0x34, 0x56, 0x78 };
static const LONG test_len = 4;

static const UBYTE test_abc[] = { 'a', 'b', 'c' };
static const LONG test_abc_len = 3;

static LONG test_total;
static LONG test_passed;
static LONG test_failed;
static BOOL suite_fail;

static void suite_begin(const char *title)
{
	test_total++;
	suite_fail = FALSE;
	printf("TEST %ld: %s\n", test_total, title);
}

static void check_ulong(const char *label, ULONG expect, ULONG actual)
{
	if (expect == actual)
	{
		printf("  PASS: %s expect=%08lX actual=%08lX\n", label, expect, actual);
	}
	else
	{
		printf("  FAIL: %s expect=%08lX actual=%08lX\n", label, expect, actual);
		suite_fail = TRUE;
	}
}

static void check_uword(const char *label, UWORD expect, UWORD actual)
{
	if (expect == actual)
	{
		printf("  PASS: %s expect=%04lX actual=%04lX\n", label,
			(ULONG)expect, (ULONG)actual);
	}
	else
	{
		printf("  FAIL: %s expect=%04lX actual=%04lX\n", label,
			(ULONG)expect, (ULONG)actual);
		suite_fail = TRUE;
	}
}

static void check_ubyte(const char *label, UBYTE expect, UBYTE actual)
{
	if (expect == actual)
	{
		printf("  PASS: %s expect=%02lX actual=%02lX\n", label,
			(ULONG)expect, (ULONG)actual);
	}
	else
	{
		printf("  FAIL: %s expect=%02lX actual=%02lX\n", label,
			(ULONG)expect, (ULONG)actual);
		suite_fail = TRUE;
	}
}

static void check_digest(const char *label, const UBYTE *expect, const UBYTE *actual, LONG len)
{
	LONG i;
	BOOL ok;

	ok = TRUE;
	for (i = 0; i < len; i++)
	{
		if (expect[i] != actual[i])
		{
			ok = FALSE;
			break;
		}
	}

	if (ok)
	{
		printf("  PASS: %s\n", label);
	}
	else
	{
		printf("  FAIL: %s digest mismatch\n", label);
		suite_fail = TRUE;
	}
}

static void check_md5(const char *label, const UBYTE *expect, const UBYTE *actual)
{
	check_digest(label, expect, actual, SIZEOF_MD5SUM);
}

static void suite_end(void)
{
	if (suite_fail)
	{
		test_failed++;
		printf("  RESULT: FAIL\n\n");
	}
	else
	{
		test_passed++;
		printf("  RESULT: PASS\n\n");
	}
}

int main(void)
{
	UBYTE *v;
	BYTE *sv;
	UBYTE md5[SIZEOF_MD5SUM];
	UBYTE sha1[SIZEOF_SHA1SUM];
	UBYTE sha256[SIZEOF_SHA256SUM];
	static const UBYTE md5_abc[SIZEOF_MD5SUM] = {
		0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
		0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72
	};
	static const UBYTE sha1_abc[SIZEOF_SHA1SUM] = {
		0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
		0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
		0x9c, 0xd0, 0xd8, 0x9d
	};
	static const UBYTE sha256_abc[SIZEOF_SHA256SUM] = {
		0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
		0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
		0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
		0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
	};

	v = (UBYTE *)test_vec;
	sv = (BYTE *)test_vec;

	printf("CRCTest - crc.library baseline checks\n");
	printf("=====================================\n\n");

	CRCBase = OpenLibrary("crc.library", VERNUM);
	if (!CRCBase)
	{
		printf("FAIL: could not open crc.library version %d\n", VERNUM);
		return 20;
	}

	suite_begin("OpenLibrary crc.library");
	printf("  PASS: base=%p version=%u revision=%u\n",
		CRCBase, CRCBase->lib_Version, CRCBase->lib_Revision);
	suite_end();

	/* CRC-32 family */
	suite_begin("DoCRC32_1 (PCompress / Olaf Barthel)");
	check_ulong("CRC32-1", 0x6B4DD184UL, DoCRC32_1(v, test_len));
	suite_end();

	suite_begin("DoCRC32_2 (Zip / GZip / LZX)");
	check_ulong("CRC32-2", 0x4A090E98UL, DoCRC32_2(v, test_len));
	suite_end();

	suite_begin("DoCRC32_3 (Brik / Ace)");
	check_ulong("CRC32-3", 0xB5F6F167UL, DoCRC32_3(v, test_len));
	suite_end();

	suite_begin("DoCRC32_4 (GPatch)");
	check_ulong("CRC32-4", 0x311CAEA0UL, DoCRC32_4(v, test_len));
	suite_end();

	suite_begin("DoCRC32_5 (BZip2)");
	check_ulong("CRC32-5", 0x207575D4UL, DoCRC32_5(v, test_len));
	suite_end();

	suite_begin("DoCRC32_6 (BZip2 inverted)");
	check_ulong("CRC32-6", 0xDF8A8A2BUL, DoCRC32_6(v, test_len));
	suite_end();

	/* CRC-16 family */
	suite_begin("DoCRC16_1 (PCompress2 / Arc / DMS)");
	check_uword("CRC16-1", 0x347B, DoCRC16_1(v, test_len));
	suite_end();

	suite_begin("DoCRC16_2 (CCITT / XModem / LU)");
	check_uword("CRC16-2", 0xB42C, DoCRC16_2(v, test_len));
	suite_end();

	suite_begin("DoCRC16_3 (Donald Kindred)");
	check_uword("CRC16-3", 0x0084, DoCRC16_3(v, test_len));
	suite_end();

	suite_begin("DoCRC16_4 (old Zoom / CompDisk)");
	check_uword("CRC16-4", 0x45BE, DoCRC16_4(v, test_len));
	suite_end();

	/* Checksum family */
	suite_begin("DoCHS32_1M (WRAP, Motorola)");
	check_ulong("CHS32-1M", 0xEDCBA987UL, DoCHS32_1M(v, test_len));
	suite_end();

	suite_begin("DoCHS32_1I (WRAP, Intel)");
	check_ulong("CHS32-1I", 0x87A9CBEDUL, DoCHS32_1I(v, test_len));
	suite_end();

	suite_begin("DoCHS32_2 (LightFileSystem)");
	check_ulong("CHS32-2", 0x000058A0UL, DoCHS32_2(v, test_len));
	suite_end();

	suite_begin("DoCHS16_1 (PowerPacker passwords)");
	check_uword("CHS16-1", 0xD74C, DoCHS16_1(v, test_len));
	suite_end();

	/* EOR family */
	suite_begin("DoEORB (byte EOR)");
	check_ubyte("EORB", 0x08, DoEORB(v, test_len));
	suite_end();

	suite_begin("DoEORWM (word EOR, Motorola)");
	check_uword("EORWM", 0x444C, DoEORWM(v, test_len));
	suite_end();

	suite_begin("DoEORWI (word EOR, Intel)");
	check_uword("EORWI", 0x4C44, DoEORWI(v, test_len));
	suite_end();

	suite_begin("DoEORLM (long EOR, Motorola)");
	check_ulong("EORLM", 0x12345678UL, DoEORLM(v, test_len));
	suite_end();

	suite_begin("DoEORLI (long EOR, Intel)");
	check_ulong("EORLI", 0x78563412UL, DoEORLI(v, test_len));
	suite_end();

	/* Sum family */
	suite_begin("DoSumSB (signed byte sum)");
	check_ulong("SumSB", 0x00000114UL, DoSumSB(sv, test_len));
	suite_end();

	suite_begin("DoSumSWM (signed word sum, Motorola)");
	check_ulong("SumSWM", 0x000068ACUL, DoSumSWM(v, test_len));
	suite_end();

	suite_begin("DoSumSWI (signed word sum, Intel)");
	check_ulong("SumSWI", 0x0000AC68UL, DoSumSWI(v, test_len));
	suite_end();

	suite_begin("DoSumUB (unsigned byte sum)");
	check_ulong("SumUB", 0x00000114UL, DoSumUB(v, test_len));
	suite_end();

	suite_begin("DoSumUWM (unsigned word sum, Motorola)");
	check_ulong("SumUWM", 0x000068ACUL, DoSumUWM(v, test_len));
	suite_end();

	suite_begin("DoSumUWI (unsigned word sum, Intel)");
	check_ulong("SumUWI", 0x0000AC68UL, DoSumUWI(v, test_len));
	suite_end();

	suite_begin("DoSumLM (long sum, Motorola)");
	check_ulong("SumLM", 0x12345678UL, DoSumLM(v, test_len));
	suite_end();

	suite_begin("DoSumLI (long sum, Intel)");
	check_ulong("SumLI", 0x78563412UL, DoSumLI(v, test_len));
	suite_end();

	/* Message digests (git / Subversion object hashing) */
	suite_begin("DoMD5Sum on \"abc\" (RFC 1321 vector)");
	DoMD5Sum((UBYTE *)test_abc, test_abc_len, md5);
	check_md5("MD5", md5_abc, md5);
	suite_end();

	suite_begin("DoSHA1 on \"abc\" (FIPS 180-1 vector)");
	DoSHA1((UBYTE *)test_abc, test_abc_len, sha1);
	check_digest("SHA1", sha1_abc, sha1, SIZEOF_SHA1SUM);
	suite_end();

	suite_begin("DoSHA256 on \"abc\" (FIPS 180-4 vector)");
	DoSHA256((UBYTE *)test_abc, test_abc_len, sha256);
	check_digest("SHA256", sha256_abc, sha256, SIZEOF_SHA256SUM);
	suite_end();

	/* POSIX / Unix checksums (GetCRC 1.19) */
	suite_begin("DoCHS16_2 (BSD sum)");
	check_uword("CHS16-2", 0x40B2U, DoCHS16_2(v, test_len));
	suite_end();

	suite_begin("DoCHS16_3 (SYSV sum)");
	check_uword("CHS16-3", 0x0114U, DoCHS16_3(v, test_len));
	suite_end();

	suite_begin("DoCRC32_7 (POSIX cksum)");
	check_ulong("CRC32-7", 0x08B5EFEBUL, DoCRC32_7(v, test_len));
	suite_end();

	/*
	 * Incremental (streaming) API.  Each streamed result must match the
	 * corresponding one-shot call over the same data.
	 */
	suite_begin("CRCDigestLength reports correct sizes");
	check_ulong("len(CRC32_2)", 0UL, CRCDigestLength(CRC_CRC32_2));
	check_ulong("len(MD5)", (ULONG)SIZEOF_MD5SUM, CRCDigestLength(CRC_MD5));
	check_ulong("len(SHA1)", (ULONG)SIZEOF_SHA1SUM, CRCDigestLength(CRC_SHA1));
	check_ulong("len(SHA256)", (ULONG)SIZEOF_SHA256SUM, CRCDigestLength(CRC_SHA256));
	suite_end();

	suite_begin("Streaming CRC32_2 (byte-at-a-time) == one-shot");
	{
		APTR h;
		ULONG streamed;
		LONG i;

		streamed = 0;
		h = CRCNew(CRC_CRC32_2);
		if (h == NULL)
		{
			printf("  FAIL: CRCNew returned NULL\n");
			suite_fail = TRUE;
		}
		else
		{
			for (i = 0; i < test_len; i++)
				CRCUpdate(h, v + i, 1);
			streamed = CRCFinal(h, NULL);
			CRCDispose(h);
			check_ulong("CRC32-2", DoCRC32_2(v, test_len), streamed);
		}
	}
	suite_end();

	suite_begin("Streaming SHA256 \"abc\" one byte at a time == vector");
	{
		APTR h;

		h = CRCNew(CRC_SHA256);
		if (h == NULL)
		{
			printf("  FAIL: CRCNew returned NULL\n");
			suite_fail = TRUE;
		}
		else
		{
			CRCUpdate(h, (UBYTE *)test_abc, 1);
			CRCUpdate(h, (UBYTE *)test_abc + 1, 1);
			CRCUpdate(h, (UBYTE *)test_abc + 2, 1);
			(void)CRCFinal(h, sha256);
			check_digest("SHA256", sha256_abc, sha256, SIZEOF_SHA256SUM);

			/* Re-use the same handle after CRCReset. */
			CRCReset(h);
			CRCUpdate(h, (UBYTE *)test_abc, test_abc_len);
			(void)CRCFinal(h, sha256);
			check_digest("SHA256 after reset", sha256_abc, sha256, SIZEOF_SHA256SUM);
			CRCDispose(h);
		}
	}
	suite_end();

	CloseLibrary(CRCBase);
	CRCBase = NULL;

	printf("Summary: %ld passed, %ld failed, %ld total\n",
		test_passed, test_failed, test_total);

	return (test_failed != 0) ? 10 : 0;
}
