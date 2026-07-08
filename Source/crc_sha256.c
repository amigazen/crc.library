/*
 * crc_sha256.c - SHA-256 message digest (FIPS PUB 180-4)
 *
 * Algorithm core adapted from Brad Conte's public-domain implementation;
 * Amiga types and one-shot crc_DoSHA256() wrapper for git object hashing.
 */

#include <exec/types.h>
#include "private/crc_internal.h"

#define SHA256_BLOCK_SIZE 64
#define SHA256_HASH_SIZE  32

struct SHA256Context
{
  ULONG state[8];
  ULONG bitlen;
  UBYTE buffer[SHA256_BLOCK_SIZE];
  ULONG buflen;
};

static const ULONG sha256_k[64] = {
  0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
  0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
  0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
  0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
  0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
  0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
  0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
  0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
  0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
  0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
  0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
  0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
  0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
  0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
  0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
  0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

#define ROTRIGHT(a, b) (((a) >> (b)) | ((a) << (32 - (b))))
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x, 2) ^ ROTRIGHT(x, 13) ^ ROTRIGHT(x, 22))
#define EP1(x) (ROTRIGHT(x, 6) ^ ROTRIGHT(x, 11) ^ ROTRIGHT(x, 25))
#define SIG0(x) (ROTRIGHT(x, 7) ^ ROTRIGHT(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x, 17) ^ ROTRIGHT(x, 19) ^ ((x) >> 10))

static void sha256_transform(struct SHA256Context *ctx, const UBYTE *data);
static void sha256_init(struct SHA256Context *ctx);
static void sha256_update(struct SHA256Context *ctx, const UBYTE *data, ULONG len);
static void sha256_final(struct SHA256Context *ctx, UBYTE hash[SHA256_HASH_SIZE]);

static void
sha256_transform(struct SHA256Context *ctx, const UBYTE *data)
{
  ULONG m[64];
  ULONG a;
  ULONG b;
  ULONG c;
  ULONG d;
  ULONG e;
  ULONG f;
  ULONG g;
  ULONG h;
  ULONG t1;
  ULONG t2;
  ULONG i;
  ULONG j;

  for (i = 0, j = 0; i < 16; i++, j += 4)
  {
    m[i] = ((ULONG)data[j] << 24)
      | ((ULONG)data[j + 1] << 16)
      | ((ULONG)data[j + 2] << 8)
      | (ULONG)data[j + 3];
  }
  for (i = 16; i < 64; i++)
  {
    m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
  }

  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];
  f = ctx->state[5];
  g = ctx->state[6];
  h = ctx->state[7];

  for (i = 0; i < 64; i++)
  {
    t1 = h + EP1(e) + CH(e, f, g) + sha256_k[i] + m[i];
    t2 = EP0(a) + MAJ(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

static void
sha256_init(struct SHA256Context *ctx)
{
  ctx->buflen = 0;
  ctx->bitlen = 0;
  ctx->state[0] = 0x6a09e667UL;
  ctx->state[1] = 0xbb67ae85UL;
  ctx->state[2] = 0x3c6ef372UL;
  ctx->state[3] = 0xa54ff53aUL;
  ctx->state[4] = 0x510e527fUL;
  ctx->state[5] = 0x9b05688cUL;
  ctx->state[6] = 0x1f83d9abUL;
  ctx->state[7] = 0x5be0cd19UL;
}

static void
sha256_update(struct SHA256Context *ctx, const UBYTE *data, ULONG len)
{
  ULONG i;

  for (i = 0; i < len; i++)
  {
    ctx->buffer[ctx->buflen] = data[i];
    ctx->buflen++;
    if (ctx->buflen == SHA256_BLOCK_SIZE)
    {
      sha256_transform(ctx, ctx->buffer);
      ctx->bitlen += 512;
      ctx->buflen = 0;
    }
  }
}

static void
sha256_final(struct SHA256Context *ctx, UBYTE hash[SHA256_HASH_SIZE])
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
    while (i < SHA256_BLOCK_SIZE)
    {
      ctx->buffer[i++] = 0;
    }
    sha256_transform(ctx, ctx->buffer);
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
  sha256_transform(ctx, ctx->buffer);

  for (i = 0; i < 4; i++)
  {
    hash[i]      = (UBYTE)((ctx->state[0] >> (24 - i * 8)) & 0xFF);
    hash[i + 4]  = (UBYTE)((ctx->state[1] >> (24 - i * 8)) & 0xFF);
    hash[i + 8]  = (UBYTE)((ctx->state[2] >> (24 - i * 8)) & 0xFF);
    hash[i + 12] = (UBYTE)((ctx->state[3] >> (24 - i * 8)) & 0xFF);
    hash[i + 16] = (UBYTE)((ctx->state[4] >> (24 - i * 8)) & 0xFF);
    hash[i + 20] = (UBYTE)((ctx->state[5] >> (24 - i * 8)) & 0xFF);
    hash[i + 24] = (UBYTE)((ctx->state[6] >> (24 - i * 8)) & 0xFF);
    hash[i + 28] = (UBYTE)((ctx->state[7] >> (24 - i * 8)) & 0xFF);
  }
}

void
crc_DoSHA256(const UBYTE *Mem, LONG Size, UBYTE Digest[SIZEOF_SHA256SUM])
{
  struct SHA256Context ctx;

  sha256_init(&ctx);
  sha256_update(&ctx, Mem, (ULONG)Size);
  sha256_final(&ctx, Digest);
}

/* Opaque sub-context wrappers for the streaming API. */
ULONG crc_sha256_ctxsize(void) { return (ULONG)sizeof(struct SHA256Context); }
void crc_sha256_init(APTR ctx) { sha256_init((struct SHA256Context *)ctx); }
void crc_sha256_update(APTR ctx, const UBYTE *data, ULONG len)
  { sha256_update((struct SHA256Context *)ctx, data, len); }
void crc_sha256_final(APTR ctx, UBYTE *digest)
  { sha256_final((struct SHA256Context *)ctx, digest); }
