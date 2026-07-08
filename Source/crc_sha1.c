/*
 * crc_sha1.c - SHA-1 message digest (FIPS PUB 180-1 / RFC 3174)
 *
 * Algorithm core adapted from Brad Conte's public-domain implementation;
 * Amiga types and one-shot crc_DoSHA1() wrapper for crc.library.
 */

#include <exec/types.h>
#include "private/crc_internal.h"

#define SHA1_BLOCK_SIZE 64
#define SHA1_HASH_SIZE  20

struct SHA1Context
{
  ULONG state[5];
  ULONG k[4];
  ULONG bitlen;
  UBYTE buffer[SHA1_BLOCK_SIZE];
  ULONG buflen;
};

#define ROTLEFT(a, b) (((a) << (b)) | ((a) >> (32 - (b))))

static void sha1_transform(struct SHA1Context *ctx, const UBYTE *data);
static void sha1_init(struct SHA1Context *ctx);
static void sha1_update(struct SHA1Context *ctx, const UBYTE *data, ULONG len);
static void sha1_final(struct SHA1Context *ctx, UBYTE hash[SHA1_HASH_SIZE]);

static void
sha1_transform(struct SHA1Context *ctx, const UBYTE *data)
{
  ULONG m[80];
  ULONG a;
  ULONG b;
  ULONG c;
  ULONG d;
  ULONG e;
  ULONG t;
  ULONG i;
  ULONG j;

  for (i = 0, j = 0; i < 16; i++, j += 4)
  {
    m[i] = ((ULONG)data[j] << 24)
      | ((ULONG)data[j + 1] << 16)
      | ((ULONG)data[j + 2] << 8)
      | (ULONG)data[j + 3];
  }
  for (i = 16; i < 80; i++)
  {
    m[i] = m[i - 3] ^ m[i - 8] ^ m[i - 14] ^ m[i - 16];
    m[i] = (m[i] << 1) | (m[i] >> 31);
  }

  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];

  for (i = 0; i < 20; i++)
  {
    t = ROTLEFT(a, 5) + ((b & c) ^ (~b & d)) + e + ctx->k[0] + m[i];
    e = d;
    d = c;
    c = ROTLEFT(b, 30);
    b = a;
    a = t;
  }
  for (i = 20; i < 40; i++)
  {
    t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + ctx->k[1] + m[i];
    e = d;
    d = c;
    c = ROTLEFT(b, 30);
    b = a;
    a = t;
  }
  for (i = 40; i < 60; i++)
  {
    t = ROTLEFT(a, 5) + ((b & c) ^ (b & d) ^ (c & d)) + e + ctx->k[2] + m[i];
    e = d;
    d = c;
    c = ROTLEFT(b, 30);
    b = a;
    a = t;
  }
  for (i = 60; i < 80; i++)
  {
    t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + ctx->k[3] + m[i];
    e = d;
    d = c;
    c = ROTLEFT(b, 30);
    b = a;
    a = t;
  }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
}

static void
sha1_init(struct SHA1Context *ctx)
{
  ctx->buflen = 0;
  ctx->bitlen = 0;
  ctx->state[0] = 0x67452301UL;
  ctx->state[1] = 0xEFCDAB89UL;
  ctx->state[2] = 0x98BADCFEUL;
  ctx->state[3] = 0x10325476UL;
  ctx->state[4] = 0xC3D2E1F0UL;
  ctx->k[0] = 0x5A827999UL;
  ctx->k[1] = 0x6ED9EBA1UL;
  ctx->k[2] = 0x8F1BBCDCUL;
  ctx->k[3] = 0xCA62C1D6UL;
}

static void
sha1_update(struct SHA1Context *ctx, const UBYTE *data, ULONG len)
{
  ULONG i;

  for (i = 0; i < len; i++)
  {
    ctx->buffer[ctx->buflen] = data[i];
    ctx->buflen++;
    if (ctx->buflen == SHA1_BLOCK_SIZE)
    {
      sha1_transform(ctx, ctx->buffer);
      ctx->bitlen += 512;
      ctx->buflen = 0;
    }
  }
}

static void
sha1_final(struct SHA1Context *ctx, UBYTE hash[SHA1_HASH_SIZE])
{
  ULONG i;

  i = ctx->buflen;

  if (ctx->buflen < 56)
  {
    ctx->buffer[i++] = 0x80;
    while (i < 56)
    {
      ctx->buffer[i++] = 0;
    }
  }
  else
  {
    ctx->buffer[i++] = 0x80;
    while (i < SHA1_BLOCK_SIZE)
    {
      ctx->buffer[i++] = 0;
    }
    sha1_transform(ctx, ctx->buffer);
    crc_bzero(ctx->buffer, 56);
    i = 0;
  }

  ctx->bitlen += ctx->buflen * 8;
  ctx->buffer[63] = (UBYTE)ctx->bitlen;
  ctx->buffer[62] = (UBYTE)(ctx->bitlen >> 8);
  ctx->buffer[61] = (UBYTE)(ctx->bitlen >> 16);
  ctx->buffer[60] = (UBYTE)(ctx->bitlen >> 24);
  ctx->buffer[59] = 0;
  ctx->buffer[58] = 0;
  ctx->buffer[57] = 0;
  ctx->buffer[56] = 0;
  sha1_transform(ctx, ctx->buffer);

  for (i = 0; i < 4; i++)
  {
    hash[i]      = (UBYTE)((ctx->state[0] >> (24 - i * 8)) & 0xFF);
    hash[i + 4]  = (UBYTE)((ctx->state[1] >> (24 - i * 8)) & 0xFF);
    hash[i + 8]  = (UBYTE)((ctx->state[2] >> (24 - i * 8)) & 0xFF);
    hash[i + 12] = (UBYTE)((ctx->state[3] >> (24 - i * 8)) & 0xFF);
    hash[i + 16] = (UBYTE)((ctx->state[4] >> (24 - i * 8)) & 0xFF);
  }
}

void
crc_DoSHA1(const UBYTE *Mem, LONG Size, UBYTE Digest[SIZEOF_SHA1SUM])
{
  struct SHA1Context ctx;

  sha1_init(&ctx);
  sha1_update(&ctx, Mem, (ULONG)Size);
  sha1_final(&ctx, Digest);
}

/* Opaque sub-context wrappers for the streaming API. */
ULONG crc_sha1_ctxsize(void) { return (ULONG)sizeof(struct SHA1Context); }
void crc_sha1_init(APTR ctx) { sha1_init((struct SHA1Context *)ctx); }
void crc_sha1_update(APTR ctx, const UBYTE *data, ULONG len)
  { sha1_update((struct SHA1Context *)ctx, data, len); }
void crc_sha1_final(APTR ctx, UBYTE *digest)
  { sha1_final((struct SHA1Context *)ctx, digest); }
