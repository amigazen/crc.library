/*
 * CheckSys - simple example for crc.library
 *
 * Builds or checks an SHA-256 index of key system directories on SYS:
 * (or another ROOT assign). By default only C:, Libs:, S:, Devs:, L:,
 * Expansion/, and System/ are indexed — use FULL to walk all of ROOT.
 *
 * Notes:
 * - This is an example program, not a security boundary. If the baseline
 *   index lives on the same volume being checked, it can be modified too.
 * - Uses dos.library directory walking (Examine/ExNext) for portability.
 * - After SCAN the index is sealed: SHA-256 stored in the file comment via
 *   SetComment(), then write-protected with SetProtection() (see dos.library
 *   autodocs). CHECK warns if the index is writable or the comment mismatches.
 */

#include <exec/types.h>
#include <exec/libraries.h>
#include <dos/dos.h>
#include <dos/dosextens.h>
#include <dos/rdargs.h>

#include <string.h>

#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/utility.h>
#include <proto/crc.h>

#include <libraries/crc.h>

#define INDEX_FILENAME "CheckSys.idx"
#define READ_BUFSIZE   8192
#define INDEX_COMMENT_PREFIX "CheckSys:"

#define TEMPLATE "SCAN/S,CHECK/S,FULL/S,ROOT/K,INDEX/K,VERBOSE/S,HELP/S"

struct Library *CRCBase;

struct ScanStats
{
	ULONG files_ok;
	ULONG files_fail;
	ULONG dirs_fail;
};

/*
 * Subdirectories under ROOT that matter for "did an installer stomp my
 * system?" checks. Prefs/, Trashcan/, T/, and Storage/ are omitted because
 * they change often and are not core OS binaries.
 */
static const char *key_dirs[] =
{
	"C",
	"Libs",
	"S",
	"Devs",
	"L",
	"Expansion",
	"System",
	NULL
};

/* Optional single files at the volume root. */
static const char *key_files[] =
{
	"MountList",
	NULL
};

static const char hexchars[] = "0123456789abcdef";

static void digest_to_hex(char *out, const UBYTE *data, LONG len)
{
	LONG i;
	UBYTE b;

	for (i = 0; i < len; i++)
	{
		b = data[i];
		out[i * 2 + 0] = hexchars[(b >> 4) & 0x0f];
		out[i * 2 + 1] = hexchars[b & 0x0f];
	}

	out[len * 2] = '\0';
}

static BOOL hash_file_sha256(const char *path, UBYTE digest[SIZEOF_SHA256SUM],
	ULONG *size_out)
{
	BPTR fh;
	APTR h;
	UBYTE *buf;
	LONG r;
	ULONG total;

	fh = 0;
	h = NULL;
	buf = NULL;
	total = 0;
	r = 0;

	fh = Open((STRPTR)path, MODE_OLDFILE);
	if (fh == 0)
		return FALSE;

	h = CRCNew(CRC_SHA256);
	if (h == NULL)
	{
		Close(fh);
		return FALSE;
	}

	buf = (UBYTE *)AllocVec(READ_BUFSIZE, MEMF_PUBLIC);
	if (buf == NULL)
	{
		CRCDispose(h);
		Close(fh);
		return FALSE;
	}

	for (;;)
	{
		r = Read(fh, buf, READ_BUFSIZE);
		if (r <= 0)
			break;
		total += (ULONG)r;
		CRCUpdate(h, buf, r);
	}

	CRCFinal(h, digest);

	FreeVec(buf);
	CRCDispose(h);
	Close(fh);

	if (size_out != NULL)
		*size_out = total;

	/* Read() returns -1 on error. */
	return (BOOL)(r >= 0);
}

/*
 * Examine a file or directory for protection bits and comment string.
 */
static BOOL examine_file(const char *path, LONG *prot_out, char *comment_out)
{
	BPTR lock;
	struct FileInfoBlock *fib;
	BOOL ok;

	lock = 0;
	fib = NULL;
	ok = FALSE;

	lock = Lock((STRPTR)path, SHARED_LOCK);
	if (lock == 0)
		return FALSE;

	fib = (struct FileInfoBlock *)AllocDosObject(DOS_FIB, NULL);
	if (fib == NULL)
		goto done;

	if (Examine(lock, fib))
	{
		if (prot_out != NULL)
			*prot_out = fib->fib_Protection;
		if (comment_out != NULL)
		{
			strncpy(comment_out, (const char *)fib->fib_Comment, 79);
			comment_out[79] = '\0';
		}
		ok = TRUE;
	}

done:
	if (fib != NULL)
		FreeDosObject(DOS_FIB, fib);
	if (lock != 0)
		UnLock(lock);

	return ok;
}

/*
 * Clear write protection so an existing index can be rebuilt.
 * Low-active FIBF_WRITE: bit set means write-protected (read-only).
 */
static BOOL prepare_index_for_write(const char *path, BPTR report)
{
	LONG prot;

	if (!examine_file(path, &prot, NULL))
		return TRUE;

	if ((prot & FIBF_WRITE) == 0)
		return TRUE;

	if (!SetProtection((STRPTR)path, prot & ~FIBF_WRITE))
	{
		if (report != 0)
			PrintFault(IoErr(), (STRPTR)"CheckSys");
		return FALSE;
	}

	if (report != 0)
		FPrintf(report, "Cleared write protection on %s for rebuild\n", (LONG)path);

	return TRUE;
}

/*
 * Hash the index, store digest in the file comment, then write-protect it.
 */
static BOOL seal_index_file(const char *path, BPTR report)
{
	UBYTE digest[SIZEOF_SHA256SUM];
	char hex[SIZEOF_SHA256SUM * 2 + 1];
	char comment[80];
	LONG prot;

	prot = 0;

	if (!hash_file_sha256(path, digest, NULL))
	{
		if (report != 0)
			FPrintf(report, "Cannot hash index file '%s' for sealing.\n", (LONG)path);
		return FALSE;
	}

	digest_to_hex(hex, digest, SIZEOF_SHA256SUM);

	strncpy(comment, INDEX_COMMENT_PREFIX, sizeof(comment) - 1);
	comment[sizeof(comment) - 1] = '\0';
	strncat(comment, hex, sizeof(comment) - strlen(comment) - 1);

	if (!SetComment((STRPTR)path, (STRPTR)comment))
	{
		if (report != 0)
			PrintFault(IoErr(), (STRPTR)"CheckSys");
		return FALSE;
	}

	(void)examine_file(path, &prot, NULL);

	if (!SetProtection((STRPTR)path, prot | FIBF_WRITE))
	{
		if (report != 0)
			PrintFault(IoErr(), (STRPTR)"CheckSys");
		return FALSE;
	}

	if (report != 0)
		FPrintf(report, "Sealed %s (write-protected, integrity comment set)\n", (LONG)path);

	return TRUE;
}

/*
 * On CHECK: warn if index is writable; verify comment matches file SHA-256.
 * Caller must ensure the index file exists (Open succeeded).
 */
static LONG check_index_seal(const char *path, BPTR report)
{
	LONG problems;
	LONG prot;
	char comment[80];
	UBYTE digest[SIZEOF_SHA256SUM];
	char hex[SIZEOF_SHA256SUM * 2 + 1];
	char expect[80];
	BPTR lock;
	struct FileInfoBlock *fib;

	problems = 0;
	prot = 0;
	comment[0] = '\0';
	lock = 0;
	fib = NULL;

	lock = Lock((STRPTR)path, SHARED_LOCK);
	if (lock == 0)
		return 0;

	fib = (struct FileInfoBlock *)AllocDosObject(DOS_FIB, NULL);
	if (fib == NULL)
		goto done;

	if (!Examine(lock, fib))
		goto done;

	/* Ignore directories and other non-file entries. */
	if (fib->fib_DirEntryType > 0)
		goto done;

	prot = fib->fib_Protection;
	strncpy(comment, (const char *)fib->fib_Comment, 79);
	comment[79] = '\0';

	if (!hash_file_sha256(path, digest, NULL))
		goto done;

	if ((prot & FIBF_WRITE) == 0)
	{
		if (report != 0)
		{
			FPrintf(report,
				"WARNING: Index '%s' is not write-protected.\n",
				(LONG)path);
		}
		problems++;
	}

	digest_to_hex(hex, digest, SIZEOF_SHA256SUM);

	strncpy(expect, INDEX_COMMENT_PREFIX, sizeof(expect) - 1);
	expect[sizeof(expect) - 1] = '\0';
	strncat(expect, hex, sizeof(expect) - strlen(expect) - 1);

	if (comment[0] == '\0')
	{
		if (report != 0)
		{
			FPrintf(report,
				"WARNING: Index '%s' has no integrity comment.\n"
				"Run 'CheckSys SCAN' to seal the index.\n",
				(LONG)path);
		}
		problems++;
	}
	else if (Stricmp((STRPTR)comment, (STRPTR)expect) != 0)
	{
		if (report != 0)
		{
			FPrintf(report,
				"TAMPER: Index '%s' comment does not match file contents.\n",
				(LONG)path);
		}
		problems++;
	}

done:
	if (fib != NULL)
		FreeDosObject(DOS_FIB, fib);
	if (lock != 0)
		UnLock(lock);

	return problems;
}

static void write_index_line(BPTR out, const char *path, const UBYTE digest[SIZEOF_SHA256SUM],
	ULONG size)
{
	char hex[SIZEOF_SHA256SUM * 2 + 1];

	digest_to_hex(hex, digest, SIZEOF_SHA256SUM);

	FPrintf(out, "sha256 %s %lu %s\n", (LONG)hex, size, (LONG)path);
}

static void write_error_line(BPTR out, const char *path)
{
	FPrintf(out, "! %s\n", (LONG)path);
}

static BOOL index_one_file(const char *path, BPTR index_out, BPTR progress,
	BOOL verbose, struct ScanStats *stats)
{
	UBYTE digest[SIZEOF_SHA256SUM];
	ULONG size;

	if (hash_file_sha256(path, digest, &size))
	{
		write_index_line(index_out, path, digest, size);
		if (stats != NULL)
			stats->files_ok++;
		if (verbose && progress != 0)
			FPrintf(progress, "  %s\n", (LONG)path);
		return TRUE;
	}

	write_error_line(index_out, path);
	if (stats != NULL)
		stats->files_fail++;
	if (progress != 0)
		FPrintf(progress, "  ! %s\n", (LONG)path);
	return FALSE;
}

static BOOL scan_dir(const char *dirpath, BPTR index_out, BPTR progress,
	BOOL verbose, struct ScanStats *stats)
{
	BPTR lock;
	struct FileInfoBlock *fib;
	BOOL ok;

	lock = 0;
	fib = NULL;
	ok = TRUE;

	lock = Lock((STRPTR)dirpath, SHARED_LOCK);
	if (lock == 0)
	{
		if (stats != NULL)
			stats->dirs_fail++;
		return FALSE;
	}

	fib = (struct FileInfoBlock *)AllocDosObject(DOS_FIB, NULL);
	if (fib == NULL)
	{
		UnLock(lock);
		if (stats != NULL)
			stats->dirs_fail++;
		return FALSE;
	}

	if (!Examine(lock, fib))
	{
		ok = FALSE;
		goto done;
	}

	if (progress != 0)
		FPrintf(progress, "Scanning %s...\n", (LONG)dirpath);

	for (;;)
	{
		char fullpath[512];

		if (!ExNext(lock, fib))
		{
			if (IoErr() == ERROR_NO_MORE_ENTRIES)
				break;
			ok = FALSE;
			break;
		}

		fullpath[0] = '\0';
		strncpy(fullpath, dirpath, sizeof(fullpath) - 1);
		fullpath[sizeof(fullpath) - 1] = '\0';

		if (!AddPart(fullpath, fib->fib_FileName, (LONG)sizeof(fullpath)))
		{
			write_error_line(index_out, fib->fib_FileName);
			if (stats != NULL)
				stats->files_fail++;
			continue;
		}

		if (fib->fib_DirEntryType > 0)
		{
			if (strcmp(fib->fib_FileName, ".") == 0 || strcmp(fib->fib_FileName, "..") == 0)
				continue;
			if (!scan_dir(fullpath, index_out, progress, verbose, stats))
			{
				write_error_line(index_out, fullpath);
				if (stats != NULL)
					stats->dirs_fail++;
			}
			continue;
		}

		(void)index_one_file(fullpath, index_out, progress, verbose, stats);
	}

done:
	if (fib != NULL)
		FreeDosObject(DOS_FIB, fib);
	if (lock != 0)
		UnLock(lock);

	return ok;
}

static BOOL path_exists(const char *path)
{
	BPTR lock;
	BOOL exists;

	lock = Lock((STRPTR)path, SHARED_LOCK);
	exists = (lock != 0);
	if (exists)
		UnLock(lock);
	return exists;
}

static BOOL scan_selective(const char *root, BPTR index_out, BPTR progress,
	BOOL verbose, struct ScanStats *stats)
{
	char path[512];
	LONG i;
	BOOL ok;

	ok = TRUE;

	for (i = 0; key_dirs[i] != NULL; i++)
	{
		path[0] = '\0';
		strncpy(path, root, sizeof(path) - 1);
		path[sizeof(path) - 1] = '\0';

		if (!AddPart(path, (STRPTR)key_dirs[i], (LONG)sizeof(path)))
			continue;

		if (!path_exists(path))
		{
			if (progress != 0)
				FPrintf(progress, "Skipping %s (not found)\n", (LONG)path);
			continue;
		}

		if (!scan_dir(path, index_out, progress, verbose, stats))
			ok = FALSE;
	}

	for (i = 0; key_files[i] != NULL; i++)
	{
		path[0] = '\0';
		strncpy(path, root, sizeof(path) - 1);
		path[sizeof(path) - 1] = '\0';

		if (!AddPart(path, (STRPTR)key_files[i], (LONG)sizeof(path)))
			continue;

		if (!path_exists(path))
			continue;

		if (progress != 0)
			FPrintf(progress, "Indexing %s...\n", (LONG)path);

		(void)index_one_file(path, index_out, progress, verbose, stats);
	}

	return ok;
}

static int hexval(char c)
{
	if (c >= '0' && c <= '9')
		return (int)(c - '0');
	if (c >= 'a' && c <= 'f')
		return (int)(c - 'a' + 10);
	if (c >= 'A' && c <= 'F')
		return (int)(c - 'A' + 10);
	return -1;
}

static BOOL hex_to_digest(UBYTE *out, const char *hex, LONG outlen)
{
	LONG i;
	int hi;
	int lo;

	for (i = 0; i < outlen; i++)
	{
		hi = hexval(hex[i * 2 + 0]);
		lo = hexval(hex[i * 2 + 1]);
		if (hi < 0 || lo < 0)
			return FALSE;
		out[i] = (UBYTE)((hi << 4) | lo);
	}

	return TRUE;
}

static char *skip_ws(char *p)
{
	while (*p == ' ' || *p == '\t')
		p++;
	return p;
}

static char *next_token(char *p)
{
	while (*p != '\0' && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r')
		p++;
	return p;
}

static void trim_eol(char *s)
{
	LONG n;

	n = (LONG)strlen(s);
	while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r'))
	{
		s[n - 1] = '\0';
		n--;
	}
}

static BOOL check_index(const char *indexfile, BPTR report_out, BOOL verbose,
	LONG *bad_out)
{
	BPTR in;
	char line[768];
	LONG bad;
	LONG total;
	ULONG io_err;

	in = 0;
	bad = 0;
	total = 0;
	io_err = 0;

	in = Open((STRPTR)indexfile, MODE_OLDFILE);
	if (in == 0)
	{
		io_err = IoErr();
		if (report_out != 0)
		{
			if (io_err == ERROR_OBJECT_NOT_FOUND)
			{
				FPrintf(report_out,
					"Index file '%s' not found.\n"
					"Run 'CheckSys SCAN' to build a baseline index first.\n",
					(LONG)indexfile);
			}
			else
			{
				FPrintf(report_out, "Cannot open index file '%s'.\n",
					(LONG)indexfile);
			}
		}
		SetIoErr(io_err);
		return FALSE;
	}

	Close(in);
	in = 0;

	bad += check_index_seal(indexfile, report_out);

	in = Open((STRPTR)indexfile, MODE_OLDFILE);
	if (in == 0)
	{
		if (report_out != 0)
			FPrintf(report_out, "Cannot reopen index file '%s'.\n", (LONG)indexfile);
		return FALSE;
	}

	if (report_out != 0)
		FPrintf(report_out, "Checking against %s...\n", (LONG)indexfile);

	while (FGets(in, line, (LONG)sizeof(line)) != 0)
	{
		char *p;
		char *t0;
		char *t1;
		char *t2;
		char *path;
		UBYTE expect_digest[SIZEOF_SHA256SUM];
		UBYTE actual_digest[SIZEOF_SHA256SUM];
		char actual_hex[SIZEOF_SHA256SUM * 2 + 1];
		ULONG expect_size;
		ULONG actual_size;
		LONG size_long;

		trim_eol(line);
		p = skip_ws(line);
		if (*p == '\0')
			continue;
		if (*p == '#')
			continue;
		if (p[0] == '!' && (p[1] == ' ' || p[1] == '\t'))
			continue;

		t0 = p;
		p = next_token(p);
		if (*p == '\0')
			continue;
		*p++ = '\0';

		p = skip_ws(p);
		t1 = p;
		p = next_token(p);
		if (*p == '\0')
			continue;
		*p++ = '\0';

		p = skip_ws(p);
		t2 = p;
		p = next_token(p);
		if (*p == '\0')
			continue;
		*p++ = '\0';

		path = skip_ws(p);
		if (*path == '\0')
			continue;

		if (Stricmp((STRPTR)t0, (STRPTR)"sha256") != 0)
			continue;
		if ((LONG)strlen(t1) != (SIZEOF_SHA256SUM * 2))
			continue;
		if (!hex_to_digest(expect_digest, t1, SIZEOF_SHA256SUM))
			continue;

		size_long = 0;
		if (StrToLong((STRPTR)t2, &size_long) == -1)
			continue;
		if (size_long < 0)
			continue;
		expect_size = (ULONG)size_long;

		total++;
		if (!hash_file_sha256(path, actual_digest, &actual_size))
		{
			bad++;
			FPrintf(report_out, "MISSING %s\n", (LONG)path);
			continue;
		}

		if (actual_size != expect_size)
		{
			bad++;
			FPrintf(report_out, "SIZE %lu!=%lu %s\n", actual_size, expect_size, (LONG)path);
			continue;
		}

		if (memcmp(actual_digest, expect_digest, SIZEOF_SHA256SUM) != 0)
		{
			bad++;
			digest_to_hex(actual_hex, actual_digest, SIZEOF_SHA256SUM);
			FPrintf(report_out, "HASH %s %s\n", (LONG)actual_hex, (LONG)path);
			continue;
		}

		if (verbose && report_out != 0)
			FPrintf(report_out, "  OK %s\n", (LONG)path);
	}

	Close(in);

	if (total == 0)
	{
		FPrintf(report_out, "Index file '%s' contains no entries.\n"
			"Run 'CheckSys SCAN' to build a baseline index first.\n",
			(LONG)indexfile);
		if (bad_out != NULL)
			*bad_out = 1;
		return FALSE;
	}

	FPrintf(report_out, "Checked %ld files, %ld problems\n", total, bad);

	if (bad_out != NULL)
		*bad_out = bad;

	return TRUE;
}

static void print_usage(void)
{
	BPTR out;

	out = Output();
	if (out == 0)
		return;

	FPrintf(out, "CheckSys - scan/check key SYS: files with crc.library\n");
	FPrintf(out, "Usage: CheckSys [SCAN|CHECK] [FULL] [ROOT <dir>] [INDEX <file>] [VERBOSE] [HELP]\n");
	FPrintf(out, "Defaults: CHECK  ROOT=SYS:  INDEX=%s\n", (LONG)INDEX_FILENAME);
	FPrintf(out, "SCAN indexes C:, Libs:, S:, Devs:, L:, Expansion/, System/ under ROOT.\n");
	FPrintf(out, "FULL scans all of ROOT recursively (slow).\n");
	FPrintf(out, "SCAN seals the index (write-protected + SHA-256 file comment).\n");
}

int main(int argc, char **argv)
{
	BPTR out;
	BOOL ok;
	ULONG openver;
	struct RDArgs *rda;
	LONG args[7];
	STRPTR root;
	STRPTR indexfile;
	BOOL help;
	BOOL scan;
	BOOL check;
	BOOL full;
	BOOL verbose;
	BPTR report;
	LONG bad;
	struct ScanStats stats;

	(void)argc;
	(void)argv;

	out = 0;
	ok = TRUE;
	openver = 2;
	rda = NULL;
	root = (STRPTR)"SYS:";
	indexfile = (STRPTR)INDEX_FILENAME;
	help = FALSE;
	scan = FALSE;
	check = FALSE;
	full = FALSE;
	verbose = FALSE;
	report = 0;
	bad = 0;

	stats.files_ok = 0;
	stats.files_fail = 0;
	stats.dirs_fail = 0;

	args[0] = 0;
	args[1] = 0;
	args[2] = 0;
	args[3] = 0;
	args[4] = 0;
	args[5] = 0;
	args[6] = 0;

	rda = ReadArgs((STRPTR)TEMPLATE, args, NULL);
	if (rda == NULL)
	{
		PrintFault(IoErr(), (STRPTR)"CheckSys");
		print_usage();
		return 20;
	}

	if (args[0] != 0)
		scan = TRUE;
	if (args[1] != 0)
		check = TRUE;
	if (args[2] != 0)
		full = TRUE;
	if (args[3] != 0)
		root = (STRPTR)args[3];
	if (args[4] != 0)
		indexfile = (STRPTR)args[4];
	if (args[5] != 0)
		verbose = TRUE;
	if (args[6] != 0)
		help = TRUE;

	if (help)
	{
		print_usage();
		FreeArgs(rda);
		return 0;
	}

	if (!scan && !check)
		check = TRUE;

	if (scan && check)
		check = FALSE;

	CRCBase = OpenLibrary((STRPTR)"crc.library", openver);
	if (CRCBase == NULL)
	{
		FreeArgs(rda);
		return 20;
	}

	report = Output();

	if (scan)
	{
		if (report != 0)
		{
			if (full)
				FPrintf(report, "Building full index of %s -> %s\n", (LONG)root, (LONG)indexfile);
			else
				FPrintf(report, "Building key-system index of %s -> %s\n", (LONG)root, (LONG)indexfile);
		}

		if (!prepare_index_for_write((const char *)indexfile, report))
		{
			CloseLibrary(CRCBase);
			CRCBase = NULL;
			FreeArgs(rda);
			return 20;
		}

		out = Open(indexfile, MODE_NEWFILE);
		if (out == 0)
		{
			if (report != 0)
				PrintFault(IoErr(), (STRPTR)"CheckSys");
			CloseLibrary(CRCBase);
			CRCBase = NULL;
			FreeArgs(rda);
			return 20;
		}

		FPrintf(out, "# CheckSys index (algo=sha256)\n");
		if (full)
			FPrintf(out, "# mode=full\n");
		else
			FPrintf(out, "# mode=key\n");
		FPrintf(out, "# root=%s\n", (LONG)root);

		if (full)
		{
			if (!scan_dir((const char *)root, out, report, verbose, &stats))
				ok = FALSE;
		}
		else
		{
			if (!scan_selective((const char *)root, out, report, verbose, &stats))
				ok = FALSE;
		}

		Close(out);

		if (!seal_index_file((const char *)indexfile, report))
			ok = FALSE;

		if (report != 0)
		{
			FPrintf(report, "Indexed %lu files", stats.files_ok);
			if (stats.files_fail != 0)
				FPrintf(report, ", %lu errors", stats.files_fail);
			if (stats.dirs_fail != 0)
				FPrintf(report, ", %lu directory errors", stats.dirs_fail);
			FPrintf(report, "\n");
		}
	}
	else
	{
		if (report == 0)
		{
			CloseLibrary(CRCBase);
			CRCBase = NULL;
			FreeArgs(rda);
			return 20;
		}

		if (!check_index((const char *)indexfile, report, verbose, &bad))
		{
			if (IoErr() != ERROR_OBJECT_NOT_FOUND)
				PrintFault(IoErr(), (STRPTR)"CheckSys");
			ok = FALSE;
		}

		if (bad != 0)
			ok = FALSE;
	}

	CloseLibrary(CRCBase);
	CRCBase = NULL;
	FreeArgs(rda);

	return ok ? 0 : 5;
}
