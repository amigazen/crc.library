/*
 * UpdateSys - complementary example to CheckSys for crc.library
 *
 * Given a candidate file path, looks up that filename in CheckSys.idx,
 * compares $VER: version/date tags, filesystem DateStamp, and SHA-256
 * against the indexed (installed) file. Offers install when:
 *   - candidate $VER is newer, or
 *   - $VER is the same (or unusable) but DateStamp is newer and SHA-256 differs
 * On yes: copies over the indexed path and updates the index seal.
 *
 * Lookup is by basename only: either the name appears in the index or it
 * does not. Multiple index hits with the same basename are treated as an
 * error (ambiguous).
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

#define INDEX_FILENAME       "CheckSys.idx"
#define READ_BUFSIZE         8192
#define INDEX_COMMENT_PREFIX "CheckSys:"
#define VER_LINE_MAX         200
#define PATH_MAX_LEN         512

#define TEMPLATE "FILE/A,INDEX/K,HELP/S"

struct Library *CRCBase;

struct VerInfo
{
	BOOL have_ver;
	ULONG major;
	ULONG minor;
	BOOL have_date;
	ULONG ymd;	/* YYMMDD for comparison */
};

struct IndexHit
{
	char path[PATH_MAX_LEN];
	char hex[SIZEOF_SHA256SUM * 2 + 1];
	char ver[VER_LINE_MAX];
	ULONG size;
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

static BOOL path_basename_match(const char *path, const char *basename)
{
	STRPTR part;

	part = FilePart((STRPTR)path);
	if (part == NULL)
		return FALSE;
	return (BOOL)(Stricmp(part, (STRPTR)basename) == 0);
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

	return (BOOL)(r >= 0);
}

static BOOL examine_file(const char *path, LONG *prot_out)
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
		ok = TRUE;
	}

done:
	if (fib != NULL)
		FreeDosObject(DOS_FIB, fib);
	if (lock != 0)
		UnLock(lock);
	return ok;
}

static BOOL get_file_datestamp(const char *path, struct DateStamp *ds_out)
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
		ds_out->ds_Days = fib->fib_Date.ds_Days;
		ds_out->ds_Minute = fib->fib_Date.ds_Minute;
		ds_out->ds_Tick = fib->fib_Date.ds_Tick;
		ok = TRUE;
	}

done:
	if (fib != NULL)
		FreeDosObject(DOS_FIB, fib);
	if (lock != 0)
		UnLock(lock);
	return ok;
}

static BOOL digest_matches_hex(const UBYTE *digest, const char *hex)
{
	char actual[SIZEOF_SHA256SUM * 2 + 1];

	digest_to_hex(actual, digest, SIZEOF_SHA256SUM);
	return (BOOL)(Stricmp((STRPTR)actual, (STRPTR)hex) == 0);
}

static void format_datestamp(BPTR out, const struct DateStamp *ds)
{
	FPrintf(out, "days=%ld mins=%ld ticks=%ld",
		ds->ds_Days, ds->ds_Minute, ds->ds_Tick);
}

static BOOL prepare_index_for_write(const char *path, BPTR report)
{
	LONG prot;

	if (!examine_file(path, &prot))
		return TRUE;

	if ((prot & FIBF_WRITE) == 0)
		return TRUE;

	if (!SetProtection((STRPTR)path, prot & ~FIBF_WRITE))
	{
		if (report != 0)
			PrintFault(IoErr(), (STRPTR)"UpdateSys");
		return FALSE;
	}

	if (report != 0)
		FPrintf(report, "Cleared write protection on %s\n", (LONG)path);

	return TRUE;
}

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
	Strncpy(comment, (STRPTR)INDEX_COMMENT_PREFIX, sizeof(comment));
	Strncat(comment, (STRPTR)hex, sizeof(comment));

	if (!SetComment((STRPTR)path, (STRPTR)comment))
	{
		if (report != 0)
			PrintFault(IoErr(), (STRPTR)"UpdateSys");
		return FALSE;
	}

	(void)examine_file(path, &prot);

	if (!SetProtection((STRPTR)path, prot | FIBF_WRITE))
	{
		if (report != 0)
			PrintFault(IoErr(), (STRPTR)"UpdateSys");
		return FALSE;
	}

	if (report != 0)
		FPrintf(report, "Sealed %s\n", (LONG)path);

	return TRUE;
}

/*
 * Parse major.minor from a token. "12.34" -> 12, 34; "12.3" -> 12, 3.
 */
static BOOL parse_version_token(const char *tok, ULONG *major, ULONG *minor)
{
	LONG maj;
	LONG min;
	const char *p;
	LONG n;

	maj = 0;
	min = 0;
	p = tok;

	if (*p < '0' || *p > '9')
		return FALSE;

	n = StrToLong((STRPTR)p, &maj);
	if (n <= 0 || maj < 0)
		return FALSE;
	p += n;
	if (*p != '.')
		return FALSE;
	p++;
	if (*p < '0' || *p > '9')
		return FALSE;
	n = StrToLong((STRPTR)p, &min);
	if (n <= 0 || min < 0)
		return FALSE;
	p += n;
	if (*p != '\0')
		return FALSE;

	*major = (ULONG)maj;
	*minor = (ULONG)min;
	return TRUE;
}

/*
 * Parse (dd.mm.yy) or (dd/mm/yy) from a $VER: line into YYMMDD.
 */
static BOOL parse_ver_date(const char *s, ULONG *ymd_out)
{
	const char *p;
	LONG day;
	LONG month;
	LONG year;
	LONG n;
	char sep;

	p = s;
	while (*p != '\0' && *p != '(')
		p++;
	if (*p != '(')
		return FALSE;
	p++;

	day = 0;
	month = 0;
	year = 0;

	n = StrToLong((STRPTR)p, &day);
	if (n <= 0 || day < 1 || day > 31)
		return FALSE;
	p += n;
	sep = *p;
	if (sep != '.' && sep != '/')
		return FALSE;
	p++;

	n = StrToLong((STRPTR)p, &month);
	if (n <= 0 || month < 1 || month > 12)
		return FALSE;
	p += n;
	if (*p != sep && *p != '.' && *p != '/')
		return FALSE;
	p++;

	n = StrToLong((STRPTR)p, &year);
	if (n <= 0 || year < 0)
		return FALSE;

	if (year < 100)
		*ymd_out = (ULONG)(year * 10000L + month * 100L + day);
	else
		*ymd_out = (ULONG)((year % 100) * 10000L + month * 100L + day);

	return TRUE;
}

static void parse_ver_line(const char *line, struct VerInfo *vi)
{
	char buf[VER_LINE_MAX];
	char *p;
	char *tok;
	char *end;

	vi->have_ver = FALSE;
	vi->major = 0;
	vi->minor = 0;
	vi->have_date = FALSE;
	vi->ymd = 0;

	Strncpy(buf, (STRPTR)line, sizeof(buf));
	p = buf;

	/* Expect leading $VER: (case-sensitive tag, Amiga convention). */
	if (p[0] != '$' || p[1] != 'V' || p[2] != 'E' || p[3] != 'R' || p[4] != ':')
		return;
	p += 5;
	p = skip_ws(p);

	while (*p != '\0')
	{
		if (*p == '(')
			break;

		tok = p;
		end = next_token(p);
		if (*end != '\0')
		{
			*end = '\0';
			p = end + 1;
		}
		else
			p = end;

		if (!vi->have_ver && parse_version_token(tok, &vi->major, &vi->minor))
			vi->have_ver = TRUE;

		p = skip_ws(p);
	}

	if (parse_ver_date(p, &vi->ymd))
		vi->have_date = TRUE;
}

/*
 * Scan a file for a $VER: tag (Amiga version string). Uses an overlap window
 * so the tag can sit across a read boundary. Optional ver_out keeps the raw
 * tag text for index storage.
 */
static BOOL scan_file_ver(const char *path, struct VerInfo *vi, char *ver_out,
	LONG ver_max, BPTR report)
{
	BPTR fh;
	UBYTE *buf;
	LONG r;
	LONG keep;
	LONG i;
	LONG start;
	char verline[VER_LINE_MAX];
	LONG vlen;
	BOOL found;

	fh = 0;
	buf = NULL;
	keep = 0;
	found = FALSE;

	vi->have_ver = FALSE;
	vi->have_date = FALSE;
	vi->major = 0;
	vi->minor = 0;
	vi->ymd = 0;
	if (ver_out != NULL && ver_max > 0)
		ver_out[0] = '\0';

	fh = Open((STRPTR)path, MODE_OLDFILE);
	if (fh == 0)
	{
		if (report != 0)
			FPrintf(report, "Cannot open '%s'\n", (LONG)path);
		return FALSE;
	}

	buf = (UBYTE *)AllocVec(READ_BUFSIZE + 8, MEMF_PUBLIC);
	if (buf == NULL)
	{
		Close(fh);
		return FALSE;
	}

	for (;;)
	{
		r = Read(fh, buf + keep, READ_BUFSIZE);
		if (r < 0)
		{
			FreeVec(buf);
			Close(fh);
			return FALSE;
		}
		if (r == 0 && keep == 0)
			break;

		r += keep;

		for (i = 0; i + 5 <= r; i++)
		{
			if (buf[i] == '$' &&
			    buf[i + 1] == 'V' &&
			    buf[i + 2] == 'E' &&
			    buf[i + 3] == 'R' &&
			    buf[i + 4] == ':')
			{
				vlen = 0;
				start = i;
				while (start < r && vlen < VER_LINE_MAX - 1)
				{
					if (buf[start] == '\0' || buf[start] == '\n' ||
					    buf[start] == '\r')
						break;
					verline[vlen++] = (char)buf[start++];
				}
				verline[vlen] = '\0';
				parse_ver_line(verline, vi);
				if (ver_out != NULL && ver_max > 0)
					Strncpy(ver_out, (STRPTR)verline, ver_max);
				found = TRUE;
				break;
			}
		}

		if (found)
			break;

		if (r == 0)
			break;

		/* Keep last 4 bytes for overlap with next Read. */
		keep = 4;
		if (keep > r)
			keep = r;
		CopyMem(buf + r - keep, buf, keep);
	}

	FreeVec(buf);
	Close(fh);
	return TRUE;
}

/*
 * Compare candidate vs installed. Return:
 *   1  candidate newer
 *   0  same / incomparable (do not install)
 *  -1  candidate older
 */
static int compare_verinfo(const struct VerInfo *cand, const struct VerInfo *inst)
{
	if (cand->have_ver && inst->have_ver)
	{
		if (cand->major > inst->major)
			return 1;
		if (cand->major < inst->major)
			return -1;
		if (cand->minor > inst->minor)
			return 1;
		if (cand->minor < inst->minor)
			return -1;

		/* Same version: prefer newer date if both present. */
		if (cand->have_date && inst->have_date)
		{
			if (cand->ymd > inst->ymd)
				return 1;
			if (cand->ymd < inst->ymd)
				return -1;
		}
		return 0;
	}

	if (cand->have_ver && !inst->have_ver)
		return 1;
	if (!cand->have_ver && inst->have_ver)
		return -1;

	if (cand->have_date && inst->have_date)
	{
		if (cand->ymd > inst->ymd)
			return 1;
		if (cand->ymd < inst->ymd)
			return -1;
	}

	return 0;
}

static void format_ver(BPTR out, const struct VerInfo *vi)
{
	if (vi->have_ver)
		FPrintf(out, "%lu.%lu", vi->major, vi->minor);
	else
		FPrintf(out, "(no $VER)");

	if (vi->have_date)
		FPrintf(out, " (%02lu.%02lu.%02lu)",
			(vi->ymd % 100),
			((vi->ymd / 100) % 100),
			(vi->ymd / 10000));
}

/*
 * Find basename in CheckSys.idx. Exactly one hit required.
 */
static LONG find_index_hit(const char *indexfile, const char *basename,
	struct IndexHit *hit, BPTR report)
{
	BPTR in;
	char line[768];
	LONG matches;
	char *p;
	char *t0;
	char *t1;
	char *t2;
	char *path;
	LONG size_long;

	matches = 0;
	in = Open((STRPTR)indexfile, MODE_OLDFILE);
	if (in == 0)
	{
		if (report != 0)
		{
			if (IoErr() == ERROR_OBJECT_NOT_FOUND)
			{
				FPrintf(report,
					"Index file '%s' not found.\n"
					"Run CheckSys SCAN first.\n",
					(LONG)indexfile);
			}
			else
				FPrintf(report, "Cannot open index '%s'.\n", (LONG)indexfile);
		}
		return -1;
	}

	while (FGets(in, line, (LONG)sizeof(line)) != 0)
	{
		trim_eol(line);
		p = skip_ws(line);
		if (*p == '\0' || *p == '#' || *p == '!')
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

		{
			char *verfield;

			verfield = NULL;
			split_path_and_ver(path, &path, &verfield);

			if (!path_basename_match(path, basename))
				continue;

			if (Stricmp((STRPTR)t0, (STRPTR)"sha256") != 0)
				continue;
			if (!hex_token_valid(t1, SIZEOF_SHA256SUM * 2))
				continue;

			size_long = 0;
			if (StrToLong((STRPTR)t2, &size_long) == -1 || size_long < 0)
				continue;

			matches++;
			if (matches == 1)
			{
				Strncpy(hit->path, (STRPTR)path, sizeof(hit->path));
				Strncpy(hit->hex, (STRPTR)t1, sizeof(hit->hex));
				hit->size = (ULONG)size_long;
				if (verfield != NULL)
					Strncpy(hit->ver, (STRPTR)verfield, sizeof(hit->ver));
				else
					hit->ver[0] = '\0';
			}
			else if (report != 0)
			{
				if (matches == 2)
				{
					FPrintf(report,
						"Ambiguous: '%s' matches more than one index entry:\n"
						"  %s\n",
						(LONG)basename, (LONG)hit->path);
				}
				FPrintf(report, "  %s\n", (LONG)path);
			}
		}
	}

	Close(in);

	if (matches == 0)
	{
		if (report != 0)
		{
			FPrintf(report,
				"'%s' is not in index '%s'.\n",
				(LONG)basename, (LONG)indexfile);
		}
		return 0;
	}
	if (matches > 1)
		return matches;

	return 1;
}

static BOOL prompt_yes(BPTR report)
{
	char ans[32];
	BPTR in;

	in = Input();
	if (in == 0)
		return FALSE;

	if (report != 0)
		FPrintf(report, "Install? (y/N): ");
	if (report != 0)
		Flush(report);

	ans[0] = '\0';
	if (FGets(in, ans, (LONG)sizeof(ans)) == 0)
		return FALSE;

	trim_eol(ans);
	if (ans[0] == 'y' || ans[0] == 'Y')
		return TRUE;
	return FALSE;
}

static BOOL clear_write_protect(const char *path, BPTR report)
{
	LONG prot;

	if (!examine_file(path, &prot))
		return TRUE;
	if ((prot & FIBF_WRITE) == 0)
		return TRUE;
	if (!SetProtection((STRPTR)path, prot & ~FIBF_WRITE))
	{
		if (report != 0)
			PrintFault(IoErr(), (STRPTR)"UpdateSys");
		return FALSE;
	}
	return TRUE;
}

static BOOL copy_file(const char *src, const char *dst, BPTR report)
{
	BPTR in;
	BPTR out;
	UBYTE *buf;
	LONG r;
	LONG w;
	BOOL ok;

	in = 0;
	out = 0;
	buf = NULL;
	ok = FALSE;

	if (!clear_write_protect(dst, report))
		return FALSE;

	in = Open((STRPTR)src, MODE_OLDFILE);
	if (in == 0)
	{
		if (report != 0)
			PrintFault(IoErr(), (STRPTR)"UpdateSys");
		return FALSE;
	}

	out = Open((STRPTR)dst, MODE_NEWFILE);
	if (out == 0)
	{
		if (report != 0)
			PrintFault(IoErr(), (STRPTR)"UpdateSys");
		Close(in);
		return FALSE;
	}

	buf = (UBYTE *)AllocVec(READ_BUFSIZE, MEMF_PUBLIC);
	if (buf == NULL)
		goto done;

	ok = TRUE;
	for (;;)
	{
		r = Read(in, buf, READ_BUFSIZE);
		if (r < 0)
		{
			ok = FALSE;
			break;
		}
		if (r == 0)
			break;
		w = Write(out, buf, r);
		if (w != r)
		{
			ok = FALSE;
			break;
		}
	}

done:
	if (buf != NULL)
		FreeVec(buf);
	if (out != 0)
		Close(out);
	if (in != 0)
		Close(in);

	if (!ok && report != 0)
		FPrintf(report, "Copy failed.\n");

	return ok;
}

/*
 * Rewrite the index line for installed_path with a new digest/size/[$VER:],
 * then seal.
 */
static BOOL update_index_entry(const char *indexfile, const char *installed_path,
	const UBYTE digest[SIZEOF_SHA256SUM], ULONG size, const char *ver,
	BPTR report)
{
	BPTR in;
	BPTR out;
	char tmpname[PATH_MAX_LEN];
	char line[768];
	char hex[SIZEOF_SHA256SUM * 2 + 1];
	BOOL replaced;
	char *p;
	char *path;
	char *pathonly;
	char *verfield;
	char *t0;
	char line_copy[768];

	in = 0;
	out = 0;
	replaced = FALSE;

	if (!prepare_index_for_write(indexfile, report))
		return FALSE;

	Strncpy(tmpname, (STRPTR)indexfile, sizeof(tmpname));
	Strncat(tmpname, (STRPTR)".new", sizeof(tmpname));

	in = Open((STRPTR)indexfile, MODE_OLDFILE);
	if (in == 0)
		return FALSE;

	out = Open((STRPTR)tmpname, MODE_NEWFILE);
	if (out == 0)
	{
		Close(in);
		return FALSE;
	}

	digest_to_hex(hex, digest, SIZEOF_SHA256SUM);

	while (FGets(in, line, (LONG)sizeof(line)) != 0)
	{
		trim_eol(line);
		Strncpy(line_copy, (STRPTR)line, sizeof(line_copy));

		p = skip_ws(line);
		if (*p == '\0' || *p == '#' || *p == '!')
		{
			FPrintf(out, "%s\n", (LONG)line_copy);
			continue;
		}

		t0 = p;
		p = next_token(p);
		if (*p == '\0')
		{
			FPrintf(out, "%s\n", (LONG)line_copy);
			continue;
		}
		*p++ = '\0';
		p = skip_ws(p);
		/* skip hex token */
		p = next_token(p);
		if (*p == '\0')
		{
			FPrintf(out, "%s\n", (LONG)line_copy);
			continue;
		}
		*p++ = '\0';
		p = skip_ws(p);
		/* skip size token */
		p = next_token(p);
		if (*p == '\0')
		{
			FPrintf(out, "%s\n", (LONG)line_copy);
			continue;
		}
		*p++ = '\0';
		path = skip_ws(p);
		pathonly = path;
		verfield = NULL;
		split_path_and_ver(path, &pathonly, &verfield);

		if (Stricmp((STRPTR)t0, (STRPTR)"sha256") == 0 &&
		    Stricmp((STRPTR)pathonly, (STRPTR)installed_path) == 0)
		{
			if (ver != NULL && ver[0] != '\0')
				FPrintf(out, "sha256 %s %lu %s %s\n",
					(LONG)hex, size, (LONG)installed_path, (LONG)ver);
			else
				FPrintf(out, "sha256 %s %lu %s\n",
					(LONG)hex, size, (LONG)installed_path);
			replaced = TRUE;
		}
		else
			FPrintf(out, "%s\n", (LONG)line_copy);
	}

	Close(in);
	Close(out);

	if (!replaced)
	{
		DeleteFile((STRPTR)tmpname);
		if (report != 0)
			FPrintf(report, "Index entry for '%s' vanished during update.\n",
				(LONG)installed_path);
		return FALSE;
	}

	if (!DeleteFile((STRPTR)indexfile))
	{
		if (report != 0)
			PrintFault(IoErr(), (STRPTR)"UpdateSys");
		DeleteFile((STRPTR)tmpname);
		return FALSE;
	}

	if (!Rename((STRPTR)tmpname, (STRPTR)indexfile))
	{
		if (report != 0)
			PrintFault(IoErr(), (STRPTR)"UpdateSys");
		return FALSE;
	}

	return seal_index_file(indexfile, report);
}

static void print_usage(void)
{
	BPTR out;

	out = Output();
	if (out == 0)
		return;

	FPrintf(out, "UpdateSys - install a newer file tracked by CheckSys.idx\n");
	FPrintf(out, "Usage: UpdateSys <file> [INDEX <file>] [HELP]\n");
	FPrintf(out, "Looks up the filename in INDEX (default %s),\n", (LONG)INDEX_FILENAME);
	FPrintf(out, "compares $VER:, file DateStamp, and SHA-256.\n");
	FPrintf(out, "Offers install if $VER is newer, or same $VER with newer\n");
	FPrintf(out, "file date and a different SHA-256 (rebuild case).\n");
}

int main(int argc, char **argv)
{
	struct RDArgs *rda;
	LONG args[3];
	STRPTR file;
	STRPTR indexfile;
	BOOL help;
	BPTR report;
	STRPTR basename;
	struct IndexHit hit;
	struct VerInfo cand;
	struct VerInfo inst;
	int cmp;
	UBYTE digest[SIZEOF_SHA256SUM];
	char cand_hex[SIZEOF_SHA256SUM * 2 + 1];
	ULONG size;
	LONG n;
	struct DateStamp cand_ds;
	struct DateStamp inst_ds;
	BOOL hash_differs;
	BOOL date_newer;
	const char *reason;

	(void)argc;
	(void)argv;

	rda = NULL;
	file = NULL;
	indexfile = (STRPTR)INDEX_FILENAME;
	help = FALSE;
	report = Output();
	basename = NULL;
	size = 0;
	cmp = 0;
	n = 0;
	hash_differs = FALSE;
	date_newer = FALSE;
	reason = NULL;
	cand_hex[0] = '\0';
	cand_ds.ds_Days = 0;
	cand_ds.ds_Minute = 0;
	cand_ds.ds_Tick = 0;
	inst_ds.ds_Days = 0;
	inst_ds.ds_Minute = 0;
	inst_ds.ds_Tick = 0;

	args[0] = 0;
	args[1] = 0;
	args[2] = 0;

	rda = ReadArgs((STRPTR)TEMPLATE, args, NULL);
	if (rda == NULL)
	{
		PrintFault(IoErr(), (STRPTR)"UpdateSys");
		print_usage();
		return 20;
	}

	file = (STRPTR)args[0];
	if (args[1] != 0)
		indexfile = (STRPTR)args[1];
	if (args[2] != 0)
		help = TRUE;

	if (help || file == NULL)
	{
		print_usage();
		FreeArgs(rda);
		return help ? 0 : 20;
	}

	CRCBase = OpenLibrary((STRPTR)"crc.library", 2);
	if (CRCBase == NULL)
	{
		if (report != 0)
			FPrintf(report, "Cannot open crc.library v2.\n");
		FreeArgs(rda);
		return 20;
	}

	basename = FilePart(file);
	if (basename == NULL || *basename == '\0')
	{
		if (report != 0)
			FPrintf(report, "Invalid FILE path.\n");
		CloseLibrary(CRCBase);
		FreeArgs(rda);
		return 20;
	}

	{
		BPTR clock;

		clock = Lock(file, SHARED_LOCK);
		if (clock == 0)
		{
			if (report != 0)
				FPrintf(report, "Candidate '%s' not found.\n", (LONG)file);
			CloseLibrary(CRCBase);
			FreeArgs(rda);
			return 20;
		}
		UnLock(clock);
	}

	hit.path[0] = '\0';
	hit.hex[0] = '\0';
	hit.ver[0] = '\0';
	hit.size = 0;

	n = find_index_hit((const char *)indexfile, (const char *)basename, &hit, report);
	if (n != 1)
	{
		CloseLibrary(CRCBase);
		FreeArgs(rda);
		return 5;
	}

	if (report != 0)
	{
		FPrintf(report, "Candidate:  %s\n", (LONG)file);
		FPrintf(report, "Installed:  %s\n", (LONG)hit.path);
	}

	{
		char cand_ver[VER_LINE_MAX];

		cand_ver[0] = '\0';

		if (!scan_file_ver((const char *)file, &cand, cand_ver, VER_LINE_MAX, report))
		{
			CloseLibrary(CRCBase);
			FreeArgs(rda);
			return 20;
		}

		if (hit.ver[0] != '\0')
		{
			parse_ver_line(hit.ver, &inst);
			if (report != 0)
				FPrintf(report, "Installed $VER (from index): %s\n", (LONG)hit.ver);
		}
		else if (!scan_file_ver(hit.path, &inst, NULL, 0, report))
		{
			CloseLibrary(CRCBase);
			FreeArgs(rda);
			return 20;
		}

		if (report != 0)
		{
			FPrintf(report, "Candidate $VER: ");
			format_ver(report, &cand);
			if (cand_ver[0] != '\0')
				FPrintf(report, " [%s]", (LONG)cand_ver);
			FPrintf(report, "\nInstalled $VER: ");
			format_ver(report, &inst);
			FPrintf(report, "\n");
		}

		/* Stash candidate $VER text for index rewrite after install. */
		Strncpy(hit.ver, (STRPTR)cand_ver, sizeof(hit.ver));
	}

	if (!hash_file_sha256((const char *)file, digest, &size))
	{
		if (report != 0)
			FPrintf(report, "Cannot hash candidate '%s'.\n", (LONG)file);
		CloseLibrary(CRCBase);
		FreeArgs(rda);
		return 20;
	}
	digest_to_hex(cand_hex, digest, SIZEOF_SHA256SUM);
	hash_differs = (BOOL)!digest_matches_hex(digest, hit.hex);

	if (!get_file_datestamp((const char *)file, &cand_ds) ||
	    !get_file_datestamp(hit.path, &inst_ds))
	{
		if (report != 0)
			FPrintf(report, "Cannot read file DateStamps.\n");
		CloseLibrary(CRCBase);
		FreeArgs(rda);
		return 20;
	}
	date_newer = (BOOL)(CompareDates(&cand_ds, &inst_ds) > 0);

	if (report != 0)
	{
		FPrintf(report, "Candidate SHA-256:  %s\n", (LONG)cand_hex);
		FPrintf(report, "Indexed SHA-256:    %s\n", (LONG)hit.hex);
		FPrintf(report, "Candidate date:     ");
		format_datestamp(report, &cand_ds);
		FPrintf(report, "\nInstalled date:     ");
		format_datestamp(report, &inst_ds);
		FPrintf(report, "\n");
	}

	cmp = compare_verinfo(&cand, &inst);
	if (cmp < 0)
	{
		if (report != 0)
			FPrintf(report, "Candidate $VER is older; nothing to do.\n");
		CloseLibrary(CRCBase);
		FreeArgs(rda);
		return 0;
	}

	if (cmp > 0)
	{
		reason = "newer $VER";
	}
	else if (hash_differs && date_newer)
	{
		/* Same $VER (or neither has a usable $VER): developer rebuild. */
		reason = "same $VER, but newer file DateStamp and different SHA-256";
	}
	else
	{
		if (report != 0)
		{
			if (!hash_differs)
				FPrintf(report, "SHA-256 matches index; nothing to do.\n");
			else if (!date_newer)
				FPrintf(report,
					"SHA-256 differs, but candidate DateStamp is not newer; nothing to do.\n");
			else
				FPrintf(report, "Candidate is not newer; nothing to do.\n");
		}
		CloseLibrary(CRCBase);
		FreeArgs(rda);
		return 0;
	}

	if (report != 0)
	{
		FPrintf(report, "Candidate is installable (%s).\n", (LONG)reason);
		FPrintf(report, "Replace %s with %s?\n", (LONG)hit.path, (LONG)file);
	}

	if (!prompt_yes(report))
	{
		if (report != 0)
			FPrintf(report, "Cancelled.\n");
		CloseLibrary(CRCBase);
		FreeArgs(rda);
		return 0;
	}

	if (!copy_file((const char *)file, hit.path, report))
	{
		CloseLibrary(CRCBase);
		FreeArgs(rda);
		return 20;
	}

	if (!hash_file_sha256(hit.path, digest, &size))
	{
		if (report != 0)
			FPrintf(report, "Installed, but failed to re-hash for index update.\n");
		CloseLibrary(CRCBase);
		FreeArgs(rda);
		return 5;
	}

	if (!update_index_entry((const char *)indexfile, hit.path, digest, size,
		hit.ver, report))
	{
		if (report != 0)
			FPrintf(report, "File installed, but index update failed.\n");
		CloseLibrary(CRCBase);
		FreeArgs(rda);
		return 5;
	}

	if (report != 0)
		FPrintf(report, "Installed and index updated.\n");

	CloseLibrary(CRCBase);
	CRCBase = NULL;
	FreeArgs(rda);
	return 0;
}
