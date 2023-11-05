#include <intrin.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define USE_CPU_EXTENSIONS true

static const unsigned int CONSTANTS[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static inline unsigned int CH(unsigned int x, unsigned int y, unsigned int z)
{
    return z ^ (x & (y ^ z));
}

static inline unsigned int MAJ(unsigned int x, unsigned int y, unsigned int z)
{
    return (x & y) | (z & (x | y));
}

static inline unsigned int ROTR(unsigned int x, unsigned int y)
{
    return (x >> y) | (x << (32 - y));
}

static inline unsigned int SIG0(unsigned int x)
{
    return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
}

static inline unsigned int SIG1(unsigned int x)
{
    return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
}

static inline unsigned int sig0(unsigned int x)
{
    return ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3);
}

static inline unsigned int sig1(unsigned int x)
{
    return ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10);
}

struct SHA256
{
    size_t length;
    size_t buffer_length;
    unsigned char buffer[64];
    unsigned int state[8];
};

void sha256_init(struct SHA256 *context)
{
    context->length = 0;
    context->buffer_length = 0;

    context->state[0] = 0x6a09e667;
    context->state[1] = 0xbb67ae85;
    context->state[2] = 0x3c6ef372;
    context->state[3] = 0xa54ff53a;
    context->state[4] = 0x510e527f;
    context->state[5] = 0x9b05688c;
    context->state[6] = 0x1f83d9ab;
    context->state[7] = 0x5be0cd19;
}

static bool cpu_supports_sha256_extensions()
{
    int cpu_info[4] = {0};
    int function = 7;
    int subfunction = 0;
    __cpuidex(cpu_info, function, subfunction);
    return (cpu_info[1] >> 29) & 1;
}

static void process_block_using_cpu_extensions(unsigned int state[8], const unsigned char *block)
{
    __m128i _state0, _state1;
    __m128i _msg, _tmp;
    __m128i _msg0, _msg1, _msg2, _msg3;
    __m128i _abef_save, _cdgh_save;
    const __m128i _mask = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);

    /* Load initial values */
    _tmp = _mm_loadu_si128((const __m128i *)&state[0]);
    _state1 = _mm_loadu_si128((const __m128i *)&state[4]);

    _tmp = _mm_shuffle_epi32(_tmp, 0xB1);           /* CDAB */
    _state1 = _mm_shuffle_epi32(_state1, 0x1B);     /* EFGH */
    _state0 = _mm_alignr_epi8(_tmp, _state1, 8);    /* ABEF */
    _state1 = _mm_blend_epi16(_state1, _tmp, 0xF0); /* CDGH */

    /* Save current state */
    _abef_save = _state0;
    _cdgh_save = _state1;

    /* Rounds 0-3 */
    _msg = _mm_loadu_si128((const __m128i *)(block + 0));
    _msg0 = _mm_shuffle_epi8(_msg, _mask);
    _msg = _mm_add_epi32(_msg0, _mm_set_epi64x(0xE9B5DBA5B5C0FBCFULL, 0x71374491428A2F98ULL));
    _state1 = _mm_sha256rnds2_epu32(_state1, _state0, _msg);
    _msg = _mm_shuffle_epi32(_msg, 0x0E);
    _state0 = _mm_sha256rnds2_epu32(_state0, _state1, _msg);

    /* Rounds 4-7 */
    _msg1 = _mm_loadu_si128((const __m128i *)(block + 16));
    _msg1 = _mm_shuffle_epi8(_msg1, _mask);
    _msg = _mm_add_epi32(_msg1, _mm_set_epi64x(0xAB1C5ED5923F82A4ULL, 0x59F111F13956C25BULL));
    _state1 = _mm_sha256rnds2_epu32(_state1, _state0, _msg);
    _msg = _mm_shuffle_epi32(_msg, 0x0E);
    _state0 = _mm_sha256rnds2_epu32(_state0, _state1, _msg);
    _msg0 = _mm_sha256msg1_epu32(_msg0, _msg1);

    /* Rounds 8-11 */
    _msg2 = _mm_loadu_si128((const __m128i *)(block + 32));
    _msg2 = _mm_shuffle_epi8(_msg2, _mask);
    _msg = _mm_add_epi32(_msg2, _mm_set_epi64x(0x550C7DC3243185BEULL, 0x12835B01D807AA98ULL));
    _state1 = _mm_sha256rnds2_epu32(_state1, _state0, _msg);
    _msg = _mm_shuffle_epi32(_msg, 0x0E);
    _state0 = _mm_sha256rnds2_epu32(_state0, _state1, _msg);
    _msg1 = _mm_sha256msg1_epu32(_msg1, _msg2);

    /* Rounds 12-15 */
    _msg3 = _mm_loadu_si128((const __m128i *)(block + 48));
    _msg3 = _mm_shuffle_epi8(_msg3, _mask);
    _msg = _mm_add_epi32(_msg3, _mm_set_epi64x(0xC19BF1749BDC06A7ULL, 0x80DEB1FE72BE5D74ULL));
    _state1 = _mm_sha256rnds2_epu32(_state1, _state0, _msg);
    _tmp = _mm_alignr_epi8(_msg3, _msg2, 4);
    _msg0 = _mm_add_epi32(_msg0, _tmp);
    _msg0 = _mm_sha256msg2_epu32(_msg0, _msg3);
    _msg = _mm_shuffle_epi32(_msg, 0x0E);
    _state0 = _mm_sha256rnds2_epu32(_state0, _state1, _msg);
    _msg2 = _mm_sha256msg1_epu32(_msg2, _msg3);

    /* Rounds 16-19 */
    _msg = _mm_add_epi32(_msg0, _mm_set_epi64x(0x240CA1CC0FC19DC6ULL, 0xEFBE4786E49B69C1ULL));
    _state1 = _mm_sha256rnds2_epu32(_state1, _state0, _msg);
    _tmp = _mm_alignr_epi8(_msg0, _msg3, 4);
    _msg1 = _mm_add_epi32(_msg1, _tmp);
    _msg1 = _mm_sha256msg2_epu32(_msg1, _msg0);
    _msg = _mm_shuffle_epi32(_msg, 0x0E);
    _state0 = _mm_sha256rnds2_epu32(_state0, _state1, _msg);
    _msg3 = _mm_sha256msg1_epu32(_msg3, _msg0);

    /* Rounds 20-23 */
    _msg = _mm_add_epi32(_msg1, _mm_set_epi64x(0x76F988DA5CB0A9DCULL, 0x4A7484AA2DE92C6FULL));
    _state1 = _mm_sha256rnds2_epu32(_state1, _state0, _msg);
    _tmp = _mm_alignr_epi8(_msg1, _msg0, 4);
    _msg2 = _mm_add_epi32(_msg2, _tmp);
    _msg2 = _mm_sha256msg2_epu32(_msg2, _msg1);
    _msg = _mm_shuffle_epi32(_msg, 0x0E);
    _state0 = _mm_sha256rnds2_epu32(_state0, _state1, _msg);
    _msg0 = _mm_sha256msg1_epu32(_msg0, _msg1);

    /* Rounds 24-27 */
    _msg = _mm_add_epi32(_msg2, _mm_set_epi64x(0xBF597FC7B00327C8ULL, 0xA831C66D983E5152ULL));
    _state1 = _mm_sha256rnds2_epu32(_state1, _state0, _msg);
    _tmp = _mm_alignr_epi8(_msg2, _msg1, 4);
    _msg3 = _mm_add_epi32(_msg3, _tmp);
    _msg3 = _mm_sha256msg2_epu32(_msg3, _msg2);
    _msg = _mm_shuffle_epi32(_msg, 0x0E);
    _state0 = _mm_sha256rnds2_epu32(_state0, _state1, _msg);
    _msg1 = _mm_sha256msg1_epu32(_msg1, _msg2);

    /* Rounds 28-31 */
    _msg = _mm_add_epi32(_msg3, _mm_set_epi64x(0x1429296706CA6351ULL, 0xD5A79147C6E00BF3ULL));
    _state1 = _mm_sha256rnds2_epu32(_state1, _state0, _msg);
    _tmp = _mm_alignr_epi8(_msg3, _msg2, 4);
    _msg0 = _mm_add_epi32(_msg0, _tmp);
    _msg0 = _mm_sha256msg2_epu32(_msg0, _msg3);
    _msg = _mm_shuffle_epi32(_msg, 0x0E);
    _state0 = _mm_sha256rnds2_epu32(_state0, _state1, _msg);
    _msg2 = _mm_sha256msg1_epu32(_msg2, _msg3);

    /* Rounds 32-35 */
    _msg = _mm_add_epi32(_msg0, _mm_set_epi64x(0x53380D134D2C6DFCULL, 0x2E1B213827B70A85ULL));
    _state1 = _mm_sha256rnds2_epu32(_state1, _state0, _msg);
    _tmp = _mm_alignr_epi8(_msg0, _msg3, 4);
    _msg1 = _mm_add_epi32(_msg1, _tmp);
    _msg1 = _mm_sha256msg2_epu32(_msg1, _msg0);
    _msg = _mm_shuffle_epi32(_msg, 0x0E);
    _state0 = _mm_sha256rnds2_epu32(_state0, _state1, _msg);
    _msg3 = _mm_sha256msg1_epu32(_msg3, _msg0);

    /* Rounds 36-39 */
    _msg = _mm_add_epi32(_msg1, _mm_set_epi64x(0x92722C8581C2C92EULL, 0x766A0ABB650A7354ULL));
    _state1 = _mm_sha256rnds2_epu32(_state1, _state0, _msg);
    _tmp = _mm_alignr_epi8(_msg1, _msg0, 4);
    _msg2 = _mm_add_epi32(_msg2, _tmp);
    _msg2 = _mm_sha256msg2_epu32(_msg2, _msg1);
    _msg = _mm_shuffle_epi32(_msg, 0x0E);
    _state0 = _mm_sha256rnds2_epu32(_state0, _state1, _msg);
    _msg0 = _mm_sha256msg1_epu32(_msg0, _msg1);

    /* Rounds 40-43 */
    _msg = _mm_add_epi32(_msg2, _mm_set_epi64x(0xC76C51A3C24B8B70ULL, 0xA81A664BA2BFE8A1ULL));
    _state1 = _mm_sha256rnds2_epu32(_state1, _state0, _msg);
    _tmp = _mm_alignr_epi8(_msg2, _msg1, 4);
    _msg3 = _mm_add_epi32(_msg3, _tmp);
    _msg3 = _mm_sha256msg2_epu32(_msg3, _msg2);
    _msg = _mm_shuffle_epi32(_msg, 0x0E);
    _state0 = _mm_sha256rnds2_epu32(_state0, _state1, _msg);
    _msg1 = _mm_sha256msg1_epu32(_msg1, _msg2);

    /* Rounds 44-47 */
    _msg = _mm_add_epi32(_msg3, _mm_set_epi64x(0x106AA070F40E3585ULL, 0xD6990624D192E819ULL));
    _state1 = _mm_sha256rnds2_epu32(_state1, _state0, _msg);
    _tmp = _mm_alignr_epi8(_msg3, _msg2, 4);
    _msg0 = _mm_add_epi32(_msg0, _tmp);
    _msg0 = _mm_sha256msg2_epu32(_msg0, _msg3);
    _msg = _mm_shuffle_epi32(_msg, 0x0E);
    _state0 = _mm_sha256rnds2_epu32(_state0, _state1, _msg);
    _msg2 = _mm_sha256msg1_epu32(_msg2, _msg3);

    /* Rounds 48-51 */
    _msg = _mm_add_epi32(_msg0, _mm_set_epi64x(0x34B0BCB52748774CULL, 0x1E376C0819A4C116ULL));
    _state1 = _mm_sha256rnds2_epu32(_state1, _state0, _msg);
    _tmp = _mm_alignr_epi8(_msg0, _msg3, 4);
    _msg1 = _mm_add_epi32(_msg1, _tmp);
    _msg1 = _mm_sha256msg2_epu32(_msg1, _msg0);
    _msg = _mm_shuffle_epi32(_msg, 0x0E);
    _state0 = _mm_sha256rnds2_epu32(_state0, _state1, _msg);
    _msg3 = _mm_sha256msg1_epu32(_msg3, _msg0);

    /* Rounds 52-55 */
    _msg = _mm_add_epi32(_msg1, _mm_set_epi64x(0x682E6FF35B9CCA4FULL, 0x4ED8AA4A391C0CB3ULL));
    _state1 = _mm_sha256rnds2_epu32(_state1, _state0, _msg);
    _tmp = _mm_alignr_epi8(_msg1, _msg0, 4);
    _msg2 = _mm_add_epi32(_msg2, _tmp);
    _msg2 = _mm_sha256msg2_epu32(_msg2, _msg1);
    _msg = _mm_shuffle_epi32(_msg, 0x0E);
    _state0 = _mm_sha256rnds2_epu32(_state0, _state1, _msg);

    /* Rounds 56-59 */
    _msg = _mm_add_epi32(_msg2, _mm_set_epi64x(0x8CC7020884C87814ULL, 0x78A5636F748F82EEULL));
    _state1 = _mm_sha256rnds2_epu32(_state1, _state0, _msg);
    _tmp = _mm_alignr_epi8(_msg2, _msg1, 4);
    _msg3 = _mm_add_epi32(_msg3, _tmp);
    _msg3 = _mm_sha256msg2_epu32(_msg3, _msg2);
    _msg = _mm_shuffle_epi32(_msg, 0x0E);
    _state0 = _mm_sha256rnds2_epu32(_state0, _state1, _msg);

    /* Rounds 60-63 */
    _msg = _mm_add_epi32(_msg3, _mm_set_epi64x(0xC67178F2BEF9A3F7ULL, 0xA4506CEB90BEFFFAULL));
    _state1 = _mm_sha256rnds2_epu32(_state1, _state0, _msg);
    _msg = _mm_shuffle_epi32(_msg, 0x0E);
    _state0 = _mm_sha256rnds2_epu32(_state0, _state1, _msg);

    /* Combine state  */
    _state0 = _mm_add_epi32(_state0, _abef_save);
    _state1 = _mm_add_epi32(_state1, _cdgh_save);

    _tmp = _mm_shuffle_epi32(_state0, 0x1B);        /* FEBA */
    _state1 = _mm_shuffle_epi32(_state1, 0xB1);     /* DCHG */
    _state0 = _mm_blend_epi16(_tmp, _state1, 0xF0); /* DCBA */
    _state1 = _mm_alignr_epi8(_state1, _tmp, 8);    /* ABEF */

    /* Save state */
    _mm_storeu_si128((__m128i *)&state[0], _state0);
    _mm_storeu_si128((__m128i *)&state[4], _state1);
}

static void prepare_message_schedule(unsigned int schedule[64], const unsigned char *block)
{
    schedule[0] = _byteswap_ulong(*(unsigned int *)(block + 0));
    schedule[1] = _byteswap_ulong(*(unsigned int *)(block + 4));
    schedule[2] = _byteswap_ulong(*(unsigned int *)(block + 8));
    schedule[3] = _byteswap_ulong(*(unsigned int *)(block + 12));
    schedule[4] = _byteswap_ulong(*(unsigned int *)(block + 16));
    schedule[5] = _byteswap_ulong(*(unsigned int *)(block + 20));
    schedule[6] = _byteswap_ulong(*(unsigned int *)(block + 24));
    schedule[7] = _byteswap_ulong(*(unsigned int *)(block + 28));
    schedule[8] = _byteswap_ulong(*(unsigned int *)(block + 32));
    schedule[9] = _byteswap_ulong(*(unsigned int *)(block + 36));
    schedule[10] = _byteswap_ulong(*(unsigned int *)(block + 40));
    schedule[11] = _byteswap_ulong(*(unsigned int *)(block + 44));
    schedule[12] = _byteswap_ulong(*(unsigned int *)(block + 48));
    schedule[13] = _byteswap_ulong(*(unsigned int *)(block + 52));
    schedule[14] = _byteswap_ulong(*(unsigned int *)(block + 56));
    schedule[15] = _byteswap_ulong(*(unsigned int *)(block + 60));
    schedule[16] = sig1(schedule[14]) + schedule[9] + sig0(schedule[1]) + schedule[0];
    schedule[17] = sig1(schedule[15]) + schedule[10] + sig0(schedule[2]) + schedule[1];
    schedule[18] = sig1(schedule[16]) + schedule[11] + sig0(schedule[3]) + schedule[2];
    schedule[19] = sig1(schedule[17]) + schedule[12] + sig0(schedule[4]) + schedule[3];
    schedule[20] = sig1(schedule[18]) + schedule[13] + sig0(schedule[5]) + schedule[4];
    schedule[21] = sig1(schedule[19]) + schedule[14] + sig0(schedule[6]) + schedule[5];
    schedule[22] = sig1(schedule[20]) + schedule[15] + sig0(schedule[7]) + schedule[6];
    schedule[23] = sig1(schedule[21]) + schedule[16] + sig0(schedule[8]) + schedule[7];
    schedule[24] = sig1(schedule[22]) + schedule[17] + sig0(schedule[9]) + schedule[8];
    schedule[25] = sig1(schedule[23]) + schedule[18] + sig0(schedule[10]) + schedule[9];
    schedule[26] = sig1(schedule[24]) + schedule[19] + sig0(schedule[11]) + schedule[10];
    schedule[27] = sig1(schedule[25]) + schedule[20] + sig0(schedule[12]) + schedule[11];
    schedule[28] = sig1(schedule[26]) + schedule[21] + sig0(schedule[13]) + schedule[12];
    schedule[29] = sig1(schedule[27]) + schedule[22] + sig0(schedule[14]) + schedule[13];
    schedule[30] = sig1(schedule[28]) + schedule[23] + sig0(schedule[15]) + schedule[14];
    schedule[31] = sig1(schedule[29]) + schedule[24] + sig0(schedule[16]) + schedule[15];
    schedule[32] = sig1(schedule[30]) + schedule[25] + sig0(schedule[17]) + schedule[16];
    schedule[33] = sig1(schedule[31]) + schedule[26] + sig0(schedule[18]) + schedule[17];
    schedule[34] = sig1(schedule[32]) + schedule[27] + sig0(schedule[19]) + schedule[18];
    schedule[35] = sig1(schedule[33]) + schedule[28] + sig0(schedule[20]) + schedule[19];
    schedule[36] = sig1(schedule[34]) + schedule[29] + sig0(schedule[21]) + schedule[20];
    schedule[37] = sig1(schedule[35]) + schedule[30] + sig0(schedule[22]) + schedule[21];
    schedule[38] = sig1(schedule[36]) + schedule[31] + sig0(schedule[23]) + schedule[22];
    schedule[39] = sig1(schedule[37]) + schedule[32] + sig0(schedule[24]) + schedule[23];
    schedule[40] = sig1(schedule[38]) + schedule[33] + sig0(schedule[25]) + schedule[24];
    schedule[41] = sig1(schedule[39]) + schedule[34] + sig0(schedule[26]) + schedule[25];
    schedule[42] = sig1(schedule[40]) + schedule[35] + sig0(schedule[27]) + schedule[26];
    schedule[43] = sig1(schedule[41]) + schedule[36] + sig0(schedule[28]) + schedule[27];
    schedule[44] = sig1(schedule[42]) + schedule[37] + sig0(schedule[29]) + schedule[28];
    schedule[45] = sig1(schedule[43]) + schedule[38] + sig0(schedule[30]) + schedule[29];
    schedule[46] = sig1(schedule[44]) + schedule[39] + sig0(schedule[31]) + schedule[30];
    schedule[47] = sig1(schedule[45]) + schedule[40] + sig0(schedule[32]) + schedule[31];
    schedule[48] = sig1(schedule[46]) + schedule[41] + sig0(schedule[33]) + schedule[32];
    schedule[49] = sig1(schedule[47]) + schedule[42] + sig0(schedule[34]) + schedule[33];
    schedule[50] = sig1(schedule[48]) + schedule[43] + sig0(schedule[35]) + schedule[34];
    schedule[51] = sig1(schedule[49]) + schedule[44] + sig0(schedule[36]) + schedule[35];
    schedule[52] = sig1(schedule[50]) + schedule[45] + sig0(schedule[37]) + schedule[36];
    schedule[53] = sig1(schedule[51]) + schedule[46] + sig0(schedule[38]) + schedule[37];
    schedule[54] = sig1(schedule[52]) + schedule[47] + sig0(schedule[39]) + schedule[38];
    schedule[55] = sig1(schedule[53]) + schedule[48] + sig0(schedule[40]) + schedule[39];
    schedule[56] = sig1(schedule[54]) + schedule[49] + sig0(schedule[41]) + schedule[40];
    schedule[57] = sig1(schedule[55]) + schedule[50] + sig0(schedule[42]) + schedule[41];
    schedule[58] = sig1(schedule[56]) + schedule[51] + sig0(schedule[43]) + schedule[42];
    schedule[59] = sig1(schedule[57]) + schedule[52] + sig0(schedule[44]) + schedule[43];
    schedule[60] = sig1(schedule[58]) + schedule[53] + sig0(schedule[45]) + schedule[44];
    schedule[61] = sig1(schedule[59]) + schedule[54] + sig0(schedule[46]) + schedule[45];
    schedule[62] = sig1(schedule[60]) + schedule[55] + sig0(schedule[47]) + schedule[46];
    schedule[63] = sig1(schedule[61]) + schedule[56] + sig0(schedule[48]) + schedule[47];
}

static void process_message_schedule(unsigned int state[8], const unsigned int schedule[64])
{
    unsigned int a, b, c, d, e, f, g, h, T1, T2;

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    /* rounds. */
    for (int i = 0; i < 64; i++)
    {
        T1 = h + SIG1(e) + CH(e, f, g) + CONSTANTS[i] + schedule[i];
        T2 = SIG0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void sha256_update(struct SHA256 *context, const unsigned char *input, size_t length)
{
    context->length += length;

    if (context->buffer_length + length < 64)
    {
        memcpy(context->buffer + context->buffer_length, input, length);
        context->buffer_length += length;
        return;
    }

    const unsigned char *block = input;
    size_t done = 0;
    unsigned int schedule[64];

    if (context->buffer_length > 0)
    {
        memcpy(context->buffer + context->buffer_length, input, 64 - context->buffer_length);
        block = context->buffer;
        done = -context->buffer_length;
    }

    if (USE_CPU_EXTENSIONS && cpu_supports_sha256_extensions())
    {
        do
        {
            process_block_using_cpu_extensions(context->state, block);
            done += 64;
            block = input + done;
        } while (done <= length - 64);
    }
    else
    {
        do
        {
            prepare_message_schedule(schedule, block);
            process_message_schedule(context->state, schedule);
            done += 64;
            block = input + done;
        } while (done <= length - 64);
    }

    context->buffer_length = length - done;
    if (done < length)
    {
        memcpy(context->buffer, input + done, context->buffer_length);
    }
}

void sha256_complete(unsigned char digest[32], struct SHA256 *context)
{
    size_t bits_count = context->length * 8;
    unsigned int schedule[64];

    context->buffer[context->buffer_length++] = 0x80;

    if (context->buffer_length >= 56)
    {
        memset(context->buffer + context->buffer_length, 0, 64 - context->buffer_length);

        if (USE_CPU_EXTENSIONS && cpu_supports_sha256_extensions())
        {
            process_block_using_cpu_extensions(context->state, context->buffer);
        }
        else
        {
            prepare_message_schedule(schedule, context->buffer);
            process_message_schedule(context->state, schedule);
        }

        context->buffer_length = 0;
    }

    memset(context->buffer + context->buffer_length, 0, 56 - context->buffer_length);
    *(unsigned long long *)(context->buffer + 56) = _byteswap_uint64(bits_count);

    if (cpu_supports_sha256_extensions())
    {
        process_block_using_cpu_extensions(context->state, context->buffer);
    }
    else
    {
        prepare_message_schedule(schedule, context->buffer);
        process_message_schedule(context->state, schedule);
    }

    *(unsigned int *)(digest + 0) = _byteswap_ulong(context->state[0]);
    *(unsigned int *)(digest + 4) = _byteswap_ulong(context->state[1]);
    *(unsigned int *)(digest + 8) = _byteswap_ulong(context->state[2]);
    *(unsigned int *)(digest + 12) = _byteswap_ulong(context->state[3]);
    *(unsigned int *)(digest + 16) = _byteswap_ulong(context->state[4]);
    *(unsigned int *)(digest + 20) = _byteswap_ulong(context->state[5]);
    *(unsigned int *)(digest + 24) = _byteswap_ulong(context->state[6]);
    *(unsigned int *)(digest + 28) = _byteswap_ulong(context->state[7]);

    context->buffer_length = 0;
}

static void print_digest(unsigned char digest[32])
{
    for (int i = 0; i < 32; i++)
    {
        printf("%02x", digest[i]);
    }
    printf("\n");
}

int main(int argc, char **argv)
{
    struct SHA256 context;
    sha256_init(&context);

    /* e0c00eec1438d3d91cdf61901416fabb43e5e0c72b23a72ebb9165848ac31a47 */
    // sha256_update(&context, "hello", 5);
    // sha256_update(&context, " ", 1);
    // sha256_update(&context, "world", 5);
    // sha256_update(&context, "1111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222223333333333333333333333333333333333333333333333333333333333333333", 181);

    /* e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 */
    // sha256_update(&context, "", 0);

    /* ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad */
    // sha256_update(&context, "abc", 3);

    /* 0b8b1f0a231239a67468d9169bef9ef09a26d3197d3ba0b4116d9afbedf83d3c */
    // sha256_update(&context, "ale,etopakistan?ale,etopakistan?ale,etopakistan?ale,etopakistan?", 64);

    /* 64ff1d020a5775f544240a6d63469818c40de3a2e5eaa6335afccdd2b9c06154 */
    sha256_update(&context, "00000", 5);
    sha256_update(&context, "11111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333333", 182);

    unsigned char digest[32];
    sha256_complete(digest, &context);
    print_digest(digest);
}