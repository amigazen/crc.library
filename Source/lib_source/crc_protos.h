# ifndef CRC_LIBRARY_PROTOS //define this to make crc.library
#  include <proto/crc.h>
# else /* CRC_LIBRARY_PROTOS */

/***********************************************************
 * exported functions
 ***********************************************************/
#   define ext_def(x) extern x __asm
/*LIB is a library prefix which allow calling of functions directly within the 
library.From outside of the library functions are called over the library base 
(register __a6), and without the LIB prefix.*/
/*__saveds is saving the near data pointer (register __a4) on every entry into
a function, and restoring it upon exit*/
/*__far gives a function a 32bit pointer (necessary for modules larger than 
32k) */

typedef signed long     LONG;
typedef unsigned long  ULONG;
typedef signed short    WORD;
typedef unsigned short UWORD;
typedef signed char     BYTE;
typedef unsigned char  UBYTE; // defined in exec/types.h

#define SIZEOF_MD5SUM  16
/// LIB...() protos
ext_def( ULONG ) LIBDoCRC32_1(
  register __a0 const UBYTE *Mem,
  register __d0 LONG Size);
ext_def( ULONG ) LIBDoCRC32_2(
  register __a0 const UBYTE *Mem,
  register __d0 LONG Size);
ext_def( ULONG ) LIBDoCRC32_3(
  register __a0 const UBYTE *Mem,
  register __d0 LONG Size);
ext_def( ULONG ) LIBDoCRC32_4(
  register __a0 const UBYTE *Mem,
  register __d0 LONG Size);
ext_def( ULONG ) LIBDoCRC32_5(
  register __a0 const UBYTE *Mem,
  register __d0 LONG Size);
ext_def( ULONG ) LIBDoCRC32_6(
  register __a0 const UBYTE *Mem,
  register __d0 LONG Size);
ext_def( UWORD ) LIBDoCRC16_1(
  register __a0 const UBYTE *Mem,
  register __d0 LONG Size);
ext_def( UWORD ) LIBDoCRC16_2(
  register __a0 const UBYTE *Mem,
  register __d0 LONG Size);
ext_def( UWORD ) LIBDoCRC16_3(
  register __a0 const UBYTE *Mem,
  register __d0 LONG Size);
ext_def( UWORD ) LIBDoCRC16_4(
  register __a0 const UBYTE *Mem,
  register __d0 LONG Size);

ext_def( ULONG ) LIBDoCHS32_1M(
  register __a0 const UBYTE *Mem,
  register __d0 LONG Size);
ext_def( ULONG ) LIBDoCHS32_1I(
  register __a0 const UBYTE *Mem,
  register __d0 LONG Size);
ext_def( ULONG ) LIBDoCHS32_2(
  register __a0 const UBYTE *Mem,
  register __d0 LONG Size);
ext_def( UWORD ) LIBDoCHS16_1(
  register __a0 const UBYTE *Mem,
  register __d0 LONG Size);

ext_def( UBYTE ) LIBDoEORB(
  register __a0 const UBYTE *Mem,
  register __d0 LONG Size);
ext_def( UWORD ) LIBDoEORWM(
  register __a0 const UBYTE *Mem,
  register __d0 LONG Size);
ext_def( UWORD ) LIBDoEORWI(
  register __a0 const UBYTE *Mem,
  register __d0 LONG Size);
ext_def( ULONG ) LIBDoEORLM(
  register __a0 const UBYTE *Mem,
  register __d0 LONG Size);
ext_def( ULONG ) LIBDoEORLI(
  register __a0 const UBYTE *Mem,
  register __d0 LONG Size);

ext_def( ULONG ) LIBDoSumSB(
  register __a0 const BYTE *Mem,
  register __d0 LONG Size);
ext_def( ULONG ) LIBDoSumSWM(
  register __a0 const UBYTE *Mem,
  register __d0 LONG Size);
ext_def( ULONG ) LIBDoSumSWI(
  register __a0 const UBYTE *Mem,
  register __d0 LONG Size);
ext_def( ULONG ) LIBDoSumUB(
  register __a0 const UBYTE *Mem,
  register __d0 LONG Size);
ext_def( ULONG ) LIBDoSumUWM(
  register __a0 const UBYTE *Mem,
  register __d0 LONG Size);
ext_def( ULONG ) LIBDoSumUWI(
  register __a0 const UBYTE *Mem,
  register __d0 LONG Size);
ext_def( ULONG ) LIBDoSumLM(
  register __a0 const UBYTE *Mem,
  register __d0 LONG Size);
ext_def( ULONG ) LIBDoSumLI(
  register __a0 const UBYTE *Mem,
  register __d0 LONG Size);

ext_def (void ) LIBmd5sum(
  register __a0 const UBYTE *Mem,
  register __d0 LONG Size,
  register __a1 UBYTE md5sum[SIZEOF_MD5SUM]);
///
/// LIBcrci_...() protos
///

# endif /* CRC_LIBRARY_PROTOS */

