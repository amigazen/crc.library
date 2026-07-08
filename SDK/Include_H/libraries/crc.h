#ifndef LIBRARIES_CRC_H
#define LIBRARIES_CRC_H
/*
**	$VER: crc.h 2.0 (7.7.26)
**
**	Public constants for crc.library
**
**	Checksum algorithms from GetCRC (PD) by Dirk Stöcker;
**	Amiga library port by Jim Sunrise (v1.0, 2006).
**	ToolKit release by amigazen project (v2.0, 2026).
*/

#ifndef EXEC_TYPES_H
#include <exec/types.h>
#endif

/*
 * Digest buffer sizes (bytes).  Pass a buffer of at least the matching size
 * to DoMD5Sum/DoSHA1/DoSHA256 and to CRCFinal() for digest algorithms.
 */
#define SIZEOF_MD5SUM    16
#define SIZEOF_SHA1SUM   20
#define SIZEOF_SHA256SUM 32

/*
 * Algorithm selectors for the incremental (streaming) API: CRCNew(),
 * CRCUpdate(), CRCFinal(), CRCReset(), CRCDispose().
 *
 * Each selector corresponds to the identically named one-shot Do* function
 * and produces a bit-identical result for the same data.  The numeric CRC and
 * checksum types return their value from CRCFinal(); the digest types
 * (CRC_MD5, CRC_SHA1, CRC_SHA256) instead write their result into the caller's
 * buffer and return zero.  Use CRCDigestLength() to distinguish the two.
 */
#define CRC_CRC32_1     0	/* PCompress, Olaf Barthel, Zoom 5, LhPak     */
#define CRC_CRC32_2     1	/* Zip, GZip, LZX, RAR, Arj                    */
#define CRC_CRC32_3     2	/* Brik (binary mode), Ace                    */
#define CRC_CRC32_4     3	/* GPatch (old)                               */
#define CRC_CRC32_5     4	/* BZip2                                      */
#define CRC_CRC32_6     5	/* BZip2 inverted                            */
#define CRC_CRC32_7     6	/* POSIX cksum utility                        */
#define CRC_CRC16_1     7	/* PCompress2, Arc, DMS, ProPack, LhA, Zoo    */
#define CRC_CRC16_2     8	/* CCITT, XModem, LU                          */
#define CRC_CRC16_3     9	/* Donald Kindred's CRC                       */
#define CRC_CRC16_4    10	/* old Zoom, CompDisk                         */
#define CRC_CHS32_1M   11	/* WRAP checksum, Motorola order              */
#define CRC_CHS32_1I   12	/* WRAP checksum, Intel order                 */
#define CRC_CHS32_2    13	/* LightFileSystem                            */
#define CRC_CHS16_1    14	/* PowerPacker passwords                      */
#define CRC_CHS16_2    15	/* BSD sum                                    */
#define CRC_CHS16_3    16	/* SYSV sum                                   */
#define CRC_EORB       17	/* byte EOR                                   */
#define CRC_EORWM      18	/* word EOR, Motorola order                   */
#define CRC_EORWI      19	/* word EOR, Intel order                      */
#define CRC_EORLM      20	/* long EOR, Motorola order                   */
#define CRC_EORLI      21	/* long EOR, Intel order                      */
#define CRC_SUMSB      22	/* signed byte sum                           */
#define CRC_SUMSWM     23	/* signed word sum, Motorola order            */
#define CRC_SUMSWI     24	/* signed word sum, Intel order               */
#define CRC_SUMUB      25	/* unsigned byte sum                         */
#define CRC_SUMUWM     26	/* unsigned word sum, Motorola order          */
#define CRC_SUMUWI     27	/* unsigned word sum, Intel order             */
#define CRC_SUMLM      28	/* long sum, Motorola order                   */
#define CRC_SUMLI      29	/* long sum, Intel order                      */
#define CRC_MD5        30	/* MD5 digest    (SIZEOF_MD5SUM bytes)        */
#define CRC_SHA1       31	/* SHA-1 digest  (SIZEOF_SHA1SUM bytes)       */
#define CRC_SHA256     32	/* SHA-256 digest(SIZEOF_SHA256SUM bytes)     */

#define CRC_TYPE_COUNT 33	/* number of valid selectors                  */

#endif /* LIBRARIES_CRC_H */
