#include <Python.h>
#include <stdint.h>
#include <string.h>

#if defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)
#include <immintrin.h>
#if defined(__GNUC__) || defined(__clang__)
#include <cpuid.h>
#endif
#if defined(_MSC_VER)
#include <intrin.h>
#endif
#endif

#if defined(__aarch64__)
#include <arm_neon.h>
#include <arm_acle.h>
#if defined(__linux__)
#include <sys/auxv.h>
#include <asm/hwcap.h>
#elif defined(__APPLE__)
#include <sys/sysctl.h>
#endif
#endif

typedef void (*sha256_compress_fn)(uint32_t state[8], const uint8_t data[64]);

typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} SHA256_CTX;

static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static uint32_t rotr(uint32_t value, uint32_t bits) {
    return (value >> bits) | (value << (32 - bits));
}

static uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

static uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static uint32_t ep0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

static uint32_t ep1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

static uint32_t sig0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

static uint32_t sig1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

static void sha256_init_state(uint32_t state[8]) {
    state[0] = 0x6a09e667;
    state[1] = 0xbb67ae85;
    state[2] = 0x3c6ef372;
    state[3] = 0xa54ff53a;
    state[4] = 0x510e527f;
    state[5] = 0x9b05688c;
    state[6] = 0x1f83d9ab;
    state[7] = 0x5be0cd19;
}

static void sha256_compress_portable(uint32_t state[8], const uint8_t data[]);

static sha256_compress_fn g_compress = sha256_compress_portable;
static const char *g_backend = "portable";

static void sha256_compress_portable(uint32_t state[8], const uint8_t data[]) {
    uint32_t m[64];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t t1, t2;
    uint32_t i;

    for (i = 0; i < 16; ++i) {
        m[i] = (uint32_t)data[i * 4] << 24 | (uint32_t)data[i * 4 + 1] << 16 |
               (uint32_t)data[i * 4 + 2] << 8 | (uint32_t)data[i * 4 + 3];
    }
    for (i = 16; i < 64; ++i) {
        m[i] = sig1(m[i - 2]) + m[i - 7] + sig0(m[i - 15]) + m[i - 16];
    }

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + ep1(e) + ch(e, f, g) + k[i] + m[i];
        t2 = ep0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
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

static void sha256_transform(SHA256_CTX *ctx, const uint8_t data[]) {
    g_compress(ctx->state, data);
}

static void sha256_init(SHA256_CTX *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    sha256_init_state(ctx->state);
}

static void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len) {
    size_t i;

    for (i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen += 1;
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(SHA256_CTX *ctx, uint8_t hash[]) {
    uint32_t i = ctx->datalen;

    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) {
            ctx->data[i++] = 0x00;
        }
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) {
            ctx->data[i++] = 0x00;
        }
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = (uint8_t)(ctx->bitlen);
    ctx->data[62] = (uint8_t)(ctx->bitlen >> 8);
    ctx->data[61] = (uint8_t)(ctx->bitlen >> 16);
    ctx->data[60] = (uint8_t)(ctx->bitlen >> 24);
    ctx->data[59] = (uint8_t)(ctx->bitlen >> 32);
    ctx->data[58] = (uint8_t)(ctx->bitlen >> 40);
    ctx->data[57] = (uint8_t)(ctx->bitlen >> 48);
    ctx->data[56] = (uint8_t)(ctx->bitlen >> 56);
    sha256_transform(ctx, ctx->data);

    for (i = 0; i < 4; ++i) {
        hash[i] = (uint8_t)((ctx->state[0] >> (24 - i * 8)) & 0xff);
        hash[i + 4] = (uint8_t)((ctx->state[1] >> (24 - i * 8)) & 0xff);
        hash[i + 8] = (uint8_t)((ctx->state[2] >> (24 - i * 8)) & 0xff);
        hash[i + 12] = (uint8_t)((ctx->state[3] >> (24 - i * 8)) & 0xff);
        hash[i + 16] = (uint8_t)((ctx->state[4] >> (24 - i * 8)) & 0xff);
        hash[i + 20] = (uint8_t)((ctx->state[5] >> (24 - i * 8)) & 0xff);
        hash[i + 24] = (uint8_t)((ctx->state[6] >> (24 - i * 8)) & 0xff);
        hash[i + 28] = (uint8_t)((ctx->state[7] >> (24 - i * 8)) & 0xff);
    }
}

static void sha256_state_to_bytes(const uint32_t state[8], uint8_t hash[32]) {
    uint32_t i;
    for (i = 0; i < 4; ++i) {
        hash[i] = (uint8_t)((state[0] >> (24 - i * 8)) & 0xff);
        hash[i + 4] = (uint8_t)((state[1] >> (24 - i * 8)) & 0xff);
        hash[i + 8] = (uint8_t)((state[2] >> (24 - i * 8)) & 0xff);
        hash[i + 12] = (uint8_t)((state[3] >> (24 - i * 8)) & 0xff);
        hash[i + 16] = (uint8_t)((state[4] >> (24 - i * 8)) & 0xff);
        hash[i + 20] = (uint8_t)((state[5] >> (24 - i * 8)) & 0xff);
        hash[i + 24] = (uint8_t)((state[6] >> (24 - i * 8)) & 0xff);
        hash[i + 28] = (uint8_t)((state[7] >> (24 - i * 8)) & 0xff);
    }
}

#if defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)
#if defined(__GNUC__) || defined(__clang__)
#define HAVE_SHA_NI 1
__attribute__((target("sha")))
static void sha256_compress_sha_ni(uint32_t state[8], const uint8_t data[64]) {
    uint32_t m[64];
    uint32_t i;
    __m128i STATE0;
    __m128i STATE1;
    __m128i ABEF_SAVE;
    __m128i CDGH_SAVE;

    for (i = 0; i < 16; ++i) {
        m[i] = (uint32_t)data[i * 4] << 24 | (uint32_t)data[i * 4 + 1] << 16 |
               (uint32_t)data[i * 4 + 2] << 8 | (uint32_t)data[i * 4 + 3];
    }
    for (i = 16; i < 64; ++i) {
        m[i] = sig1(m[i - 2]) + m[i - 7] + sig0(m[i - 15]) + m[i - 16];
    }

    STATE0 = _mm_loadu_si128((const __m128i *)&state[0]);
    STATE1 = _mm_loadu_si128((const __m128i *)&state[4]);
    ABEF_SAVE = STATE0;
    CDGH_SAVE = STATE1;

    for (i = 0; i < 64; i += 4) {
        __m128i MSG = _mm_set_epi32((int)m[i + 3], (int)m[i + 2], (int)m[i + 1], (int)m[i]);
        __m128i KMSG = _mm_set_epi32((int)k[i + 3], (int)k[i + 2], (int)k[i + 1], (int)k[i]);
        MSG = _mm_add_epi32(MSG, KMSG);
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    }

    STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
    STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);
    _mm_storeu_si128((__m128i *)&state[0], STATE0);
    _mm_storeu_si128((__m128i *)&state[4], STATE1);
}
#else
#define HAVE_SHA_NI 0
#endif
#else
#define HAVE_SHA_NI 0
#endif

#if defined(__aarch64__)
#if defined(__GNUC__) || defined(__clang__)
#define HAVE_ARM_CRYPTO 1
__attribute__((target("crypto")))
static void sha256_compress_armv8(uint32_t state[8], const uint8_t data[64]) {
    uint32x4_t STATE0, STATE1, TMP0;
    uint32x4_t MSG0, MSG1, MSG2, MSG3;
    uint32x4_t ABEF_SAVE, CDGH_SAVE;

    STATE0 = vld1q_u32(&state[0]); /* ABCD */
    STATE1 = vld1q_u32(&state[4]); /* EFGH */
    ABEF_SAVE = STATE0;
    CDGH_SAVE = STATE1;

    MSG0 = vld1q_u32((const uint32_t *)(data + 0));
    MSG1 = vld1q_u32((const uint32_t *)(data + 16));
    MSG2 = vld1q_u32((const uint32_t *)(data + 32));
    MSG3 = vld1q_u32((const uint32_t *)(data + 48));

    MSG0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG0)));
    MSG1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG1)));
    MSG2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG2)));
    MSG3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG3)));

#define RND(MSG, KIDX)                                    \
    TMP0 = vaddq_u32(MSG, vld1q_u32(&k[KIDX]));           \
    STATE1 = vsha256hq_u32(STATE1, STATE0, TMP0);         \
    STATE0 = vsha256h2q_u32(STATE0, STATE1, TMP0);

    RND(MSG0, 0);
    RND(MSG1, 4);
    RND(MSG2, 8);
    RND(MSG3, 12);

    for (int i = 16; i < 64; i += 16) {
        MSG0 = vsha256su0q_u32(MSG0, MSG1);
        MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);
        RND(MSG0, i + 0);

        MSG1 = vsha256su0q_u32(MSG1, MSG2);
        MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);
        RND(MSG1, i + 4);

        MSG2 = vsha256su0q_u32(MSG2, MSG3);
        MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);
        RND(MSG2, i + 8);

        MSG3 = vsha256su0q_u32(MSG3, MSG0);
        MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);
        RND(MSG3, i + 12);
    }

#undef RND

    STATE0 = vaddq_u32(STATE0, ABEF_SAVE);
    STATE1 = vaddq_u32(STATE1, CDGH_SAVE);

    vst1q_u32(&state[0], STATE0);
    vst1q_u32(&state[4], STATE1);
}
#else
#define HAVE_ARM_CRYPTO 0
#endif
#else
#define HAVE_ARM_CRYPTO 0
#endif

static int cpu_supports_sha_ni(void) {
#if HAVE_SHA_NI
#if defined(_MSC_VER)
    int info[4];
    __cpuidex(info, 7, 0);
    return (info[1] & (1 << 29)) != 0;
#elif defined(__GNUC__) || defined(__clang__)
    unsigned int eax = 0;
    unsigned int ebx = 0;
    unsigned int ecx = 0;
    unsigned int edx = 0;
    if (!__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        return 0;
    }
    return (ebx & (1u << 29)) != 0;
#else
    return 0;
#endif
#else
    return 0;
#endif
}

static int cpu_supports_arm_crypto(void) {
#if HAVE_ARM_CRYPTO
#if defined(__linux__)
#ifdef HWCAP_SHA2
    unsigned long caps = getauxval(AT_HWCAP);
    return (caps & HWCAP_SHA2) != 0;
#else
    return 0;
#endif
#elif defined(__APPLE__)
    int val = 0;
    size_t len = sizeof(val);
    if (sysctlbyname("hw.optional.arm.FEAT_SHA2", &val, &len, NULL, 0) == 0 && val) {
        return 1;
    }
    val = 0;
    len = sizeof(val);
    if (sysctlbyname("hw.optional.arm.sha2", &val, &len, NULL, 0) == 0 && val) {
        return 1;
    }
    /* Assume available on Apple Silicon; self-test will verify correctness. */
    return 1;
#else
    return 0;
#endif
#else
    return 0;
#endif
}

static void sha256_select_backend(void) {
#if HAVE_SHA_NI || HAVE_ARM_CRYPTO
    uint8_t block[64];
    uint32_t ref_state[8];
    uint32_t test_state[8];
    size_t idx = 0;
#endif
#if HAVE_SHA_NI
    if (cpu_supports_sha_ni()) {
        for (idx = 0; idx < sizeof(block); ++idx) {
            block[idx] = (uint8_t)idx;
        }
        sha256_init_state(ref_state);
        sha256_init_state(test_state);
        sha256_compress_portable(ref_state, block);
        sha256_compress_sha_ni(test_state, block);
        if (memcmp(ref_state, test_state, sizeof(ref_state)) == 0) {
            g_compress = sha256_compress_sha_ni;
            g_backend = "sha_ni";
            return;
        }
        g_backend = "sha_ni_selftest_fail";
    }
#endif
#if HAVE_ARM_CRYPTO
    if (cpu_supports_arm_crypto()) {
        for (idx = 0; idx < sizeof(block); ++idx) {
            block[idx] = (uint8_t)idx;
        }
        sha256_init_state(ref_state);
        sha256_init_state(test_state);
        sha256_compress_portable(ref_state, block);
        sha256_compress_armv8(test_state, block);
        if (memcmp(ref_state, test_state, sizeof(ref_state)) == 0) {
            g_compress = sha256_compress_armv8;
            g_backend = "armv8_crypto";
            return;
        }
        g_backend = "armv8_selftest_fail";
    }
#endif
    g_compress = sha256_compress_portable;
    if (g_backend == NULL || g_backend[0] == '\0' ||
        (strcmp(g_backend, "sha_ni_selftest_fail") != 0 &&
         strcmp(g_backend, "armv8_selftest_fail") != 0)) {
        g_backend = "portable";
    }
}
static void sha256d_bytes(const uint8_t *data, size_t len, uint8_t out[32]) {
    uint8_t hash1[32];
    SHA256_CTX ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, hash1);

    sha256_init(&ctx);
    sha256_update(&ctx, hash1, 32);
    sha256_final(&ctx, out);
}

static PyObject *py_sha256d(PyObject *self, PyObject *args) {
    Py_buffer view;
    uint8_t hash2[32];

    if (!PyArg_ParseTuple(args, "y*", &view)) {
        return NULL;
    }

    sha256d_bytes((const uint8_t *)view.buf, (size_t)view.len, hash2);

    PyBuffer_Release(&view);
    return PyBytes_FromStringAndSize((const char *)hash2, 32);
}

static PyObject *py_scan_hashes(PyObject *self, PyObject *args) {
    Py_buffer header_prefix;
    Py_buffer target;
    unsigned long long start_nonce = 0;
    unsigned long long count = 0;
    PyObject *results = NULL;
    unsigned long long i = 0;
    uint8_t block1[64];
    uint8_t block2[64];
    uint8_t hash1[32];
    uint8_t hash2[32];
    uint8_t hash_block[64];
    uint32_t midstate[8];
    uint32_t state1[8];
    uint32_t state2[8];
    const uint8_t *target_bytes = NULL;
    const uint8_t *prefix_bytes = NULL;
    uint64_t bitlen = 0;

    if (!PyArg_ParseTuple(args, "y*KKy*", &header_prefix, &start_nonce, &count, &target)) {
        return NULL;
    }
    if (header_prefix.len != 76) {
        PyBuffer_Release(&header_prefix);
        PyBuffer_Release(&target);
        PyErr_SetString(PyExc_ValueError, "header_prefix must be 76 bytes");
        return NULL;
    }
    if (target.len != 32) {
        PyBuffer_Release(&header_prefix);
        PyBuffer_Release(&target);
        PyErr_SetString(PyExc_ValueError, "target must be 32 bytes");
        return NULL;
    }
    if (start_nonce >= 0x100000000ULL) {
        PyBuffer_Release(&header_prefix);
        PyBuffer_Release(&target);
        PyErr_SetString(PyExc_ValueError, "start_nonce out of range");
        return NULL;
    }
    if (count > 0x100000000ULL - start_nonce) {
        count = 0x100000000ULL - start_nonce;
    }

    prefix_bytes = (const uint8_t *)header_prefix.buf;
    memcpy(block1, prefix_bytes, 64);
    memset(block2, 0, sizeof(block2));
    memcpy(block2, prefix_bytes + 64, 12);
    block2[16] = 0x80;
    bitlen = 80ULL * 8ULL;
    block2[56] = (uint8_t)(bitlen >> 56);
    block2[57] = (uint8_t)(bitlen >> 48);
    block2[58] = (uint8_t)(bitlen >> 40);
    block2[59] = (uint8_t)(bitlen >> 32);
    block2[60] = (uint8_t)(bitlen >> 24);
    block2[61] = (uint8_t)(bitlen >> 16);
    block2[62] = (uint8_t)(bitlen >> 8);
    block2[63] = (uint8_t)(bitlen);

    memset(hash_block, 0, sizeof(hash_block));
    hash_block[32] = 0x80;
    bitlen = 32ULL * 8ULL;
    hash_block[56] = (uint8_t)(bitlen >> 56);
    hash_block[57] = (uint8_t)(bitlen >> 48);
    hash_block[58] = (uint8_t)(bitlen >> 40);
    hash_block[59] = (uint8_t)(bitlen >> 32);
    hash_block[60] = (uint8_t)(bitlen >> 24);
    hash_block[61] = (uint8_t)(bitlen >> 16);
    hash_block[62] = (uint8_t)(bitlen >> 8);
    hash_block[63] = (uint8_t)(bitlen);

    sha256_init_state(midstate);
    g_compress(midstate, block1);

    target_bytes = (const uint8_t *)target.buf;
    results = PyList_New(0);
    if (!results) {
        PyBuffer_Release(&header_prefix);
        PyBuffer_Release(&target);
        return NULL;
    }

    for (i = 0; i < count; ++i) {
        uint32_t nonce = (uint32_t)(start_nonce + i);
        block2[12] = (uint8_t)(nonce & 0xff);
        block2[13] = (uint8_t)((nonce >> 8) & 0xff);
        block2[14] = (uint8_t)((nonce >> 16) & 0xff);
        block2[15] = (uint8_t)((nonce >> 24) & 0xff);

        memcpy(state1, midstate, sizeof(midstate));
        g_compress(state1, block2);
        sha256_state_to_bytes(state1, hash1);

        memcpy(hash_block, hash1, 32);
        sha256_init_state(state2);
        g_compress(state2, hash_block);
        sha256_state_to_bytes(state2, hash2);

        if (memcmp(hash2, target_bytes, 32) <= 0) {
            PyObject *py_nonce = PyLong_FromUnsignedLong(nonce);
            PyObject *py_hash = PyBytes_FromStringAndSize((const char *)hash2, 32);
            PyObject *pair = NULL;
            if (!py_nonce || !py_hash) {
                Py_XDECREF(py_nonce);
                Py_XDECREF(py_hash);
                Py_DECREF(results);
                results = NULL;
                break;
            }
            pair = PyTuple_New(2);
            if (!pair) {
                Py_DECREF(py_nonce);
                Py_DECREF(py_hash);
                Py_DECREF(results);
                results = NULL;
                break;
            }
            PyTuple_SET_ITEM(pair, 0, py_nonce);
            PyTuple_SET_ITEM(pair, 1, py_hash);
            if (PyList_Append(results, pair) != 0) {
                Py_DECREF(pair);
                Py_DECREF(results);
                results = NULL;
                break;
            }
            Py_DECREF(pair);
        }
    }

    PyBuffer_Release(&header_prefix);
    PyBuffer_Release(&target);
    return results;
}

static PyMethodDef methods[] = {
    {"sha256d", py_sha256d, METH_VARARGS, "Double SHA-256 hash."},
    {"scan_hashes", py_scan_hashes, METH_VARARGS, "Scan nonces for SHA256d hashes below target."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef module = {
    PyModuleDef_HEAD_INIT,
    "_sha256d",
    "Native SHA256d backend.",
    -1,
    methods
};

PyMODINIT_FUNC PyInit__sha256d(void) {
    PyObject *mod = PyModule_Create(&module);
    if (!mod) {
        return NULL;
    }
    sha256_select_backend();
    PyModule_AddStringConstant(mod, "backend", g_backend);
    return mod;
}
