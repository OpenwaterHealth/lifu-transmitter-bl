#include "sha256.h"

#define ROTRIGHT(a, b) (((a) >> (b)) | ((a) << (32U - (b))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x, 2U) ^ ROTRIGHT(x, 13U) ^ ROTRIGHT(x, 22U))
#define EP1(x) (ROTRIGHT(x, 6U) ^ ROTRIGHT(x, 11U) ^ ROTRIGHT(x, 25U))
#define SIG0(x) (ROTRIGHT(x, 7U) ^ ROTRIGHT(x, 18U) ^ ((x) >> 3U))
#define SIG1(x) (ROTRIGHT(x, 17U) ^ ROTRIGHT(x, 19U) ^ ((x) >> 10U))

static const uint32_t k[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U};

static void sha256_transform(sha256_ctx_t *ctx, const uint8_t data[])
{
    uint32_t m[64];
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t e;
    uint32_t f;
    uint32_t g;
    uint32_t h;
    uint32_t i;
    uint32_t t1;
    uint32_t t2;

    for (i = 0U; i < 16U; ++i)
    {
        m[i] = ((uint32_t)data[(i * 4U) + 0U] << 24U) |
               ((uint32_t)data[(i * 4U) + 1U] << 16U) |
               ((uint32_t)data[(i * 4U) + 2U] << 8U) |
               ((uint32_t)data[(i * 4U) + 3U]);
    }
    for (; i < 64U; ++i)
    {
        m[i] = SIG1(m[i - 2U]) + m[i - 7U] + SIG0(m[i - 15U]) + m[i - 16U];
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0U; i < 64U; ++i)
    {
        t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
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

void sha256_init(sha256_ctx_t *ctx)
{
    ctx->datalen = 0U;
    ctx->bitlen = 0U;
    ctx->state[0] = 0x6a09e667U;
    ctx->state[1] = 0xbb67ae85U;
    ctx->state[2] = 0x3c6ef372U;
    ctx->state[3] = 0xa54ff53aU;
    ctx->state[4] = 0x510e527fU;
    ctx->state[5] = 0x9b05688cU;
    ctx->state[6] = 0x1f83d9abU;
    ctx->state[7] = 0x5be0cd19U;
}

void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len)
{
    size_t i;
    for (i = 0U; i < len; ++i)
    {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64U)
        {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512U;
            ctx->datalen = 0U;
        }
    }
}

void sha256_final(sha256_ctx_t *ctx, uint8_t hash[32])
{
    uint32_t i;
    uint32_t j;

    i = ctx->datalen;

    if (ctx->datalen < 56U)
    {
        ctx->data[i++] = 0x80U;
        while (i < 56U)
        {
            ctx->data[i++] = 0x00U;
        }
    }
    else
    {
        ctx->data[i++] = 0x80U;
        while (i < 64U)
        {
            ctx->data[i++] = 0x00U;
        }
        sha256_transform(ctx, ctx->data);
        for (i = 0U; i < 56U; ++i)
        {
            ctx->data[i] = 0x00U;
        }
    }

    ctx->bitlen += (uint64_t)ctx->datalen * 8ULL;

    ctx->data[63] = (uint8_t)(ctx->bitlen);
    ctx->data[62] = (uint8_t)(ctx->bitlen >> 8U);
    ctx->data[61] = (uint8_t)(ctx->bitlen >> 16U);
    ctx->data[60] = (uint8_t)(ctx->bitlen >> 24U);
    ctx->data[59] = (uint8_t)(ctx->bitlen >> 32U);
    ctx->data[58] = (uint8_t)(ctx->bitlen >> 40U);
    ctx->data[57] = (uint8_t)(ctx->bitlen >> 48U);
    ctx->data[56] = (uint8_t)(ctx->bitlen >> 56U);
    sha256_transform(ctx, ctx->data);

    for (j = 0U; j < 4U; ++j)
    {
        hash[j + 0U] = (uint8_t)((ctx->state[0] >> (24U - (j * 8U))) & 0xffU);
        hash[j + 4U] = (uint8_t)((ctx->state[1] >> (24U - (j * 8U))) & 0xffU);
        hash[j + 8U] = (uint8_t)((ctx->state[2] >> (24U - (j * 8U))) & 0xffU);
        hash[j + 12U] = (uint8_t)((ctx->state[3] >> (24U - (j * 8U))) & 0xffU);
        hash[j + 16U] = (uint8_t)((ctx->state[4] >> (24U - (j * 8U))) & 0xffU);
        hash[j + 20U] = (uint8_t)((ctx->state[5] >> (24U - (j * 8U))) & 0xffU);
        hash[j + 24U] = (uint8_t)((ctx->state[6] >> (24U - (j * 8U))) & 0xffU);
        hash[j + 28U] = (uint8_t)((ctx->state[7] >> (24U - (j * 8U))) & 0xffU);
    }
}
