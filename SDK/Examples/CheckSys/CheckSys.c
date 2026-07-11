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
 * - SCAN captures $VER: in the same read pass as hashing and stores it on
 *   each index line when present.
 */

#include <exec/types.h>
#include <exec/libraries.h>
#include <dos/dos.h>
#include <dos/dosextens.h>
#include <dos/rdargs.h>

#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/utility.h>
#include <proto/crc.h>

#include <libraries/crc.h>

#define INDEX_FILENAME "CheckSys.idx"
#define READ_BUFSIZE   8192
#define INDEX_COMMENT_PREFIX "CheckSys:"
#define VER_LINE_MAX   200

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

static BOOL is_dot_entry(const char *name)
{
	if (name[0] == '.' && name[1] == '\0')
		return TRUE;
	if (name[0] == '.' && name[1] == '.' && name[2] == '\0')
		return TRUE;
	return FALSE;
}

static BOOL digest_equal(const UBYTE *a, const UBYTE *b, LONG len)
{
	LONG i;

	for (i = 0; i < len; i++)
	{
		if (a[i] != b[i])
			return FALSE;
	}
	return TRUE;
}

static BOOL hex_token_valid(const char *hex, LONG expect_chars)
{
	LONG i;

	for (i = 0; i < expect_chars; i++)
	{
		if (hexval(hex[i]) < 0)
			return FALSE;
	}
	if (hex[expect_chars] != '\0')
		return FALSE;
	return TRUE;
}

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

/*
 * Split "path [$VER:...]" so CHECK/Open use only the path. Optional $VER:
 * field begins at the first " $VER:" / "\t$VER:" after the path.
 */
static void split_path_and_ver(char *rest, char **path_out, char **ver_out)
{
	char *p;

	*path_out = rest;
	*ver_out = NULL;

	p = rest;
	while (*p != '\0')
	{
		if (p[0] == '$' && p[1] == 'V' && p[2] == 'E' && p[3] == 'R' &&
		    p[4] == ':')
		{
			if (p > rest && (p[-1] == ' ' || p[-1] == '\t'))
			{
				p[-1] = '\0';
				*ver_out = p;
				return;
			}
		}
		p++;
	}
}

/*
 * Streaming SHA-256. If ver_out is non-NULL, also search the same buffers for
 * a $VER: tag (overlap window so the tag can sit on a Read boundary).
 */
static BOOL hash_file_sha256(const char *path, UBYTE digest[SIZEOF_SHA256SUM],
	ULONG *size_out, char *ver_out, LONG ver_max)
{
	BPTR fh;
	APTR h;
	UBYTE *buf;
	LONG r;
	LONG avail;
	ULONG total;
	LONG keep;
	LONG i;
	LONG start;
	LONG vlen;
	BOOL found_ver;

	fh = 0;
	h = NULL;
	buf = NULL;
	total = 0;
	keep = 0;
	found_ver = FALSE;

	if (ver_out != NULL && ver_max > 0)
		ver_out[0] = '\0';

	fh = Open((STRPTR)path, MODE_OLDFILE);
	if (fh == 0)
		return FALSE;

	h = CRCNew(CRC_SHA256);
	if (h == NULL)
	{
		Close(fh);
		return FALSE;
	}

	buf = (UBYTE *)AllocVec(READ_BUFSIZE + 8, MEMF_PUBLIC);
	if (buf == NULL)
	{
		CRCDispose(h);
		Close(fh);
		return FALSE;
	}

	for (;;)
	{
		r = Read(fh, buf + keep, READ_BUFSIZE);
		if (r < 0)
		{
			FreeVec(buf);
			CRCDispose(h);
			Close(fh);
			return FALSE;
		}
		if (r == 0)
			break;

		total += (ULONG)r;
		CRCUpdate(h, buf + keep, r);

		avail = keep + r;

		if (ver_out != NULL && !found_ver)
		{
			for (i = 0; i + 5 <= avail; i++)
			{
				if (buf[i] == '$' &&
				    buf[i + 1] == 'V' &&
				    buf[i + 2] == 'E' &&
				    buf[i + 3] == 'R' &&
				    buf[i + 4] == ':')
				{
					vlen = 0;
					start = i;
					while (start < avail && vlen < ver_max - 1)
					{
						if (buf[start] == '\0' || buf[start] == '\n' ||
						    buf[start] == '\r')
							break;
						ver_out[vlen++] = (char)buf[start++];
					}
					ver_out[vlen] = '\0';
					found_ver = TRUE;
					break;
				}
			}
		}

		keep = 4;
		if (keep > avail)
			keep = avail;
		CopyMem(buf + avail - keep, buf, keep);
	}

	CRCFinal(h, digest);

	FreeVec(buf);
	CRCDispose(h);
	Close(fh);

	if (size_out != NULL)
		*size_out = total;

	return TRUE;
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
			Strncpy(comment_out, (STRPTR)fib->fib_Comment, 80);
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

	if (!hash_file_sha256(path, digest, NULL, NULL, 0))
	{
		if (report != 0)
			FPrintf(report, "Cannot hash index file '%s' for sealing.\n", (LONG)path);
		return FALSE;
	}

	digest_to_hex(hex, digest, SIZEOF_SHA256SUM);

	Strncpy(comment, (STRPTR)INDEX_COMMENT_PREFIX, sizeof(comment));
	Strncat(comment, (STRPTR)hex, sizeof(comment));

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
	Strncpy(comment, (STRPTR)fib->fib_Comment, 80);

	if (!hash_file_sha256(path, digest, NULL, NULL, 0))
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

	Strncpy(expect, (STRPTR)INDEX_COMMENT_PREFIX, sizeof(expect));
	Strncat(expect, (STRPTR)hex, sizeof(expect));

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
	ULONG size, const char *ver)
{
	char hex[SIZEOF_SHA256SUM * 2 + 1];

	digest_to_hex(hex, digest, SIZEOF_SHA256SUM);

	if (ver != NULL && ver[0] != '\0')
		FPrintf(out, "sha256 %s %lu %s %s\n", (LONG)hex, size, (LONG)path, (LONG)ver);
	else
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
	char ver[VER_LINE_MAX];

	ver[0] = '\0';

	if (hash_file_sha256(path, digest, &size, ver, VER_LINE_MAX))
	{
		write_index_line(index_out, path, digest, size, ver);
		if (stats != NULL)
			stats->files_ok++;
		if (verbose && progress != 0)
		{
			if (ver[0] != '\0')
				FPrintf(progress, "  %s  [%s]\n", (LONG)path, (LONG)ver);
			else
				FPrintf(progress, "  %s\n", (LONG)path);
		}
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

		Strncpy(fullpath, (STRPTR)dirpath, sizeof(fullpath));

		if (!AddPart(fullpath, fib->fib_FileName, (LONG)sizeof(fullpath)))
		{
			write_error_line(index_out, fib->fib_FileName);
			if (stats != NULL)
				stats->files_fail++;
			continue;
		}

		if (fib->fib_DirEntryType > 0)
		{
			if (is_dot_entry(fib->fib_FileName))
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
		Strncpy(path, (STRPTR)root, sizeof(path));

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
		Strncpy(path, (STRPTR)root, sizeof(path));

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
	char *p;

	p = s;
	while (*p != '\0')
		p++;
	while (p > s && (p[-1] == '\n' || p[-1] == '\r'))
	{
		p--;
		*p = '\0';
	}
}

static void report_corrupt_line(BPTR report, LONG lineno, const char *line)
{
	if (report == 0)
		return;
	FPrintf(report, "CORRUPT line %ld: %s\n", lineno, (LONG)line);
}

static BOOL check_index(const char *indexfile, BPTR report_out, BOOL verbose,
	LONG *bad_out)
{
	BPTR in;
	char line[768];
	char line_copy[768];
	LONG bad;
	LONG corrupt;
	LONG file_bad;
	LONG total;
	LONG lineno;
	ULONG io_err;

	in = 0;
	bad = 0;
	corrupt = 0;
	file_bad = 0;
	total = 0;
	lineno = 0;
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

	bad = check_index_seal(indexfile, report_out);

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

		lineno++;
		trim_eol(line);
		p = skip_ws(line);
		if (*p == '\0')
			continue;
		if (*p == '#')
			continue;
		if (p[0] == '!' && (p[1] == ' ' || p[1] == '\t'))
			continue;

		Strncpy(line_copy, (STRPTR)line, sizeof(line_copy));

		t0 = p;
		p = next_token(p);
		if (*p == '\0')
		{
			corrupt++;
			bad++;
			report_corrupt_line(report_out, lineno, line_copy);
			continue;
		}
		*p++ = '\0';

		p = skip_ws(p);
		t1 = p;
		p = next_token(p);
		if (*p == '\0')
		{
			corrupt++;
			bad++;
			report_corrupt_line(report_out, lineno, line_copy);
			continue;
		}
		*p++ = '\0';

		p = skip_ws(p);
		t2 = p;
		p = next_token(p);
		if (*p == '\0')
		{
			corrupt++;
			bad++;
			report_corrupt_line(report_out, lineno, line_copy);
			continue;
		}
		*p++ = '\0';

		path = skip_ws(p);
		if (*path == '\0')
		{
			corrupt++;
			bad++;
			report_corrupt_line(report_out, lineno, line_copy);
			continue;
		}

		{
			char *verfield;

			verfield = NULL;
			split_path_and_ver(path, &path, &verfield);
			(void)verfield;
		}

		if (*path == '\0')
		{
			corrupt++;
			bad++;
			report_corrupt_line(report_out, lineno, line_copy);
			continue;
		}

		if (Stricmp((STRPTR)t0, (STRPTR)"sha256") != 0)
		{
			corrupt++;
			bad++;
			report_corrupt_line(report_out, lineno, line_copy);
			continue;
		}
		if (!hex_token_valid(t1, SIZEOF_SHA256SUM * 2))
		{
			corrupt++;
			bad++;
			report_corrupt_line(report_out, lineno, line_copy);
			continue;
		}
		if (!hex_to_digest(expect_digest, t1, SIZEOF_SHA256SUM))
		{
			corrupt++;
			bad++;
			report_corrupt_line(report_out, lineno, line_copy);
			continue;
		}

		size_long = 0;
		if (StrToLong((STRPTR)t2, &size_long) == -1)
		{
			corrupt++;
			bad++;
			report_corrupt_line(report_out, lineno, line_copy);
			continue;
		}
		if (size_long < 0)
		{
			corrupt++;
			bad++;
			report_corrupt_line(report_out, lineno, line_copy);
			continue;
		}
		expect_size = (ULONG)size_long;

		total++;
		if (!hash_file_sha256(path, actual_digest, &actual_size, NULL, 0))
		{
			file_bad++;
			bad++;
			FPrintf(report_out, "MISSING %s\n", (LONG)path);
			continue;
		}

		if (actual_size != expect_size)
		{
			file_bad++;
			bad++;
			FPrintf(report_out, "SIZE %lu!=%lu %s\n", actual_size, expect_size, (LONG)path);
			continue;
		}

		if (!digest_equal(actual_digest, expect_digest, SIZEOF_SHA256SUM))
		{
			file_bad++;
			bad++;
			digest_to_hex(actual_hex, actual_digest, SIZEOF_SHA256SUM);
			FPrintf(report_out, "HASH %s %s\n", (LONG)actual_hex, (LONG)path);
			continue;
		}

		if (verbose && report_out != 0)
			FPrintf(report_out, "  OK %s\n", (LONG)path);
	}

	Close(in);

	if (total == 0 && corrupt == 0)
	{
		FPrintf(report_out, "Index file '%s' contains no entries.\n"
			"Run 'CheckSys SCAN' to build a baseline index first.\n",
			(LONG)indexfile);
		if (bad_out != NULL)
			*bad_out = 1;
		return FALSE;
	}

	if (total == 0 && corrupt != 0)
	{
		FPrintf(report_out, "Index file '%s' has %ld corrupt lines, no valid entries.\n",
			(LONG)indexfile, corrupt);
		if (bad_out != NULL)
			*bad_out = bad;
		return FALSE;
	}

	FPrintf(report_out, "Checked %ld files, %ld file problems, %ld corrupt lines\n",
		total, file_bad, corrupt);

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
		FPrintf(out, "# fields=sha256 hex size path [$VER:]\n");
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
