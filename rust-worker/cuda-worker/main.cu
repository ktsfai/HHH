/*
 * hash256-cuda-worker
 * NVIDIA GPU 挖矿后端，与 hash256-rust-worker 接口完全相同。
 * 编译：make（需要 nvcc）
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <cuda_runtime.h>

typedef unsigned long long u64;
typedef unsigned int       u32;
typedef unsigned char      u8;

/* ── keccak 常量 ───────────────────────────────────────────────────────── */

__constant__ u32 KECCAKF_ROTC[24] = {
     1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
};

__constant__ u32 KECCAKF_PILN[24] = {
    10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4,
    15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1
};

__constant__ u64 KECCAKF_RNDC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

/* ── 数据结构（与 Rust 侧 #[repr(C)] 完全一致） ──────────────────────── */

struct Params {
    u64 challenge[4];
    u64 nonce_prefix[2];
    u64 difficulty[4];
    u64 counter_hi;
    u64 counter_lo;
    u32 batch_size;
    u32 _padding;
};

struct Result {
    u32 found;
    u32 gid;
    u64 digest[4];
};

/* ── GPU 函数 ─────────────────────────────────────────────────────────── */

__device__ __forceinline__ u64 rotl64(u64 x, u32 n) {
    return (x << n) | (x >> (64 - n));
}

__device__ __forceinline__ u64 bswap64(u64 x) {
    return ((x & 0x00000000000000ffULL) << 56) |
           ((x & 0x000000000000ff00ULL) << 40) |
           ((x & 0x0000000000ff0000ULL) << 24) |
           ((x & 0x00000000ff000000ULL) <<  8) |
           ((x & 0x000000ff00000000ULL) >>  8) |
           ((x & 0x0000ff0000000000ULL) >> 24) |
           ((x & 0x00ff000000000000ULL) >> 40) |
           ((x & 0xff00000000000000ULL) >> 56);
}

__device__ void keccakf(u64 st[25]) {
    u64 bc[5], t;
    for (u32 round = 0; round < 24; ++round) {
        for (u32 i = 0; i < 5; ++i)
            bc[i] = st[i] ^ st[i+5] ^ st[i+10] ^ st[i+15] ^ st[i+20];
        for (u32 i = 0; i < 5; ++i) {
            t = bc[(i+4)%5] ^ rotl64(bc[(i+1)%5], 1);
            st[i]    ^= t; st[i+5]  ^= t;
            st[i+10] ^= t; st[i+15] ^= t; st[i+20] ^= t;
        }
        t = st[1];
        for (u32 i = 0; i < 24; ++i) {
            u32 j = KECCAKF_PILN[i];
            bc[0] = st[j];
            st[j] = rotl64(t, KECCAKF_ROTC[i]);
            t = bc[0];
        }
        for (u32 row = 0; row < 25; row += 5) {
            for (u32 i = 0; i < 5; ++i) bc[i] = st[row+i];
            for (u32 i = 0; i < 5; ++i)
                st[row+i] = bc[i] ^ ((~bc[(i+1)%5]) & bc[(i+2)%5]);
        }
        st[0] ^= KECCAKF_RNDC[round];
    }
}

__global__ void hash256_search(const Params* __restrict__ params,
                                Result*       __restrict__ result) {
    u32 gid = blockIdx.x * blockDim.x + threadIdx.x;
    if (gid >= params->batch_size) return;

    u64 counter_lo = params->counter_lo + (u64)gid;
    u64 carry      = (counter_lo < params->counter_lo) ? 1ULL : 0ULL;
    u64 counter_hi = params->counter_hi + carry;

    u64 st[25];
    for (u32 i = 0; i < 25; ++i) st[i] = 0ULL;

    st[0] = params->challenge[0];
    st[1] = params->challenge[1];
    st[2] = params->challenge[2];
    st[3] = params->challenge[3];
    st[4] = params->nonce_prefix[0];
    st[5] = params->nonce_prefix[1];
    st[6] = bswap64(counter_hi);
    st[7] = bswap64(counter_lo);
    st[8]  ^= 0x01ULL;
    st[16] ^= 0x8000000000000000ULL;

    keccakf(st);

    u64 w0 = bswap64(st[0]);
    u64 w1 = bswap64(st[1]);
    u64 w2 = bswap64(st[2]);
    u64 w3 = bswap64(st[3]);

    /* 比较 digest < difficulty（大端 256-bit 整数比较） */
    bool lt = false;
    do {
        if (w0 < params->difficulty[0]) { lt = true;  break; }
        if (w0 > params->difficulty[0]) break;
        if (w1 < params->difficulty[1]) { lt = true;  break; }
        if (w1 > params->difficulty[1]) break;
        if (w2 < params->difficulty[2]) { lt = true;  break; }
        if (w2 > params->difficulty[2]) break;
        if (w3 < params->difficulty[3])   lt = true;
    } while (0);

    if (!lt) return;

    if (atomicCAS(&result->found, 0u, 1u) == 0u) {
        result->gid       = gid;
        result->digest[0] = w0;
        result->digest[1] = w1;
        result->digest[2] = w2;
        result->digest[3] = w3;
    }
}

/* ── 主机辅助函数 ─────────────────────────────────────────────────────── */

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

static void hex_encode(const u8* data, int len, char* out) {
    static const char HEX[] = "0123456789abcdef";
    out[0] = '0'; out[1] = 'x';
    for (int i = 0; i < len; ++i) {
        out[2 + i*2]     = HEX[data[i] >> 4];
        out[2 + i*2 + 1] = HEX[data[i] & 0xf];
    }
    out[2 + len*2] = '\0';
}

static int parse_hex(const char* s, u8* out, int len) {
    if (s[0] == '0' && s[1] == 'x') s += 2;
    if ((int)strlen(s) != len * 2) return -1;
    for (int i = 0; i < len; ++i) {
        char b[3] = { s[i*2], s[i*2+1], '\0' };
        out[i] = (u8)strtol(b, NULL, 16);
    }
    return 0;
}

static void emit_ready(void) {
    printf("{\"type\":\"ready\",\"version\":\"0.1.0\",\"threads\":1,\"backend\":\"cuda\"}\n");
    fflush(stdout);
}

static void emit_progress(u64 hashes, double hashrate, long long elapsed_ms) {
    printf("{\"type\":\"progress\",\"hashes\":%llu,\"hashrate\":%.2f,\"elapsed_ms\":%lld}\n",
           (unsigned long long)hashes, hashrate, elapsed_ms);
    fflush(stdout);
}

static void emit_hit(const char* nonce_hex, const char* digest_hex,
                     u64 hashes, long long elapsed_ms) {
    printf("{\"type\":\"hit\",\"nonce_hex\":\"%s\",\"digest_hex\":\"%s\","
           "\"hashes\":%llu,\"elapsed_ms\":%lld}\n",
           nonce_hex, digest_hex, (unsigned long long)hashes, elapsed_ms);
    fflush(stdout);
}

static void emit_stopped(u64 hashes, long long elapsed_ms) {
    printf("{\"type\":\"stopped\",\"hashes\":%llu,\"elapsed_ms\":%lld}\n",
           (unsigned long long)hashes, elapsed_ms);
    fflush(stdout);
}

static void emit_error(const char* msg) {
    printf("{\"type\":\"error\",\"message\":\"%s\"}\n", msg);
    fflush(stdout);
}

#define CUDA_CHECK(call) do {                                          \
    cudaError_t _e = (call);                                           \
    if (_e != cudaSuccess) {                                           \
        char _buf[256];                                                \
        snprintf(_buf, sizeof(_buf), "CUDA error: %s",                 \
                 cudaGetErrorString(_e));                              \
        emit_error(_buf);                                              \
        exit(1);                                                       \
    }                                                                  \
} while (0)

/* ── main ─────────────────────────────────────────────────────────────── */

int main(int argc, char* argv[]) {
    u8  challenge[32] = {0};
    u8  difficulty[32] = {0};
    u32 batch_size  = 8388608u;   /* 8 M（NVIDIA GPU 默认） */
    u64 progress_ms = 1000u;
    int got_challenge = 0, got_difficulty = 0;

    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--challenge") && i+1 < argc) {
            if (parse_hex(argv[++i], challenge, 32)) {
                emit_error("invalid --challenge"); return 1;
            }
            got_challenge = 1;
        } else if (!strcmp(argv[i], "--difficulty") && i+1 < argc) {
            if (parse_hex(argv[++i], difficulty, 32)) {
                emit_error("invalid --difficulty"); return 1;
            }
            got_difficulty = 1;
        } else if (!strcmp(argv[i], "--batch-size") && i+1 < argc) {
            batch_size = (u32)atol(argv[++i]);
            if (batch_size == 0) batch_size = 8388608u;
        } else if (!strcmp(argv[i], "--progress-ms") && i+1 < argc) {
            progress_ms = (u64)atoll(argv[++i]);
        } else if ((!strcmp(argv[i], "--threads") ||
                    !strcmp(argv[i], "--backend")) && i+1 < argc) {
            ++i; /* 忽略 */
        }
    }

    if (!got_challenge || !got_difficulty) {
        emit_error("missing --challenge or --difficulty");
        return 1;
    }

    emit_ready();

    /* 分配显存 */
    Params* d_params;
    Result* d_result;
    CUDA_CHECK(cudaMalloc(&d_params, sizeof(Params)));
    CUDA_CHECK(cudaMalloc(&d_result, sizeof(Result)));

    /* 构建 host 参数模板 */
    Params h_params;
    memset(&h_params, 0, sizeof(h_params));

    /* challenge：LE u64（对应 Rust bytes_to_u64x4_le） */
    for (int i = 0; i < 4; ++i) {
        u64 v = 0;
        for (int j = 0; j < 8; ++j)
            v |= (u64)challenge[i*8+j] << (j*8);
        h_params.challenge[i] = v;
    }

    /* difficulty：BE u64（对应 Rust bytes_to_u64x4_be） */
    for (int i = 0; i < 4; ++i) {
        u64 v = 0;
        for (int j = 0; j < 8; ++j)
            v = (v << 8) | difficulty[i*8+j];
        h_params.difficulty[i] = v;
    }

    h_params.batch_size = batch_size;

    /* 随机 nonce 前缀（16 字节） */
    u8 prefix[16] = {0};
    FILE* urandom = fopen("/dev/urandom", "rb");
    if (urandom) { fread(prefix, 1, 16, urandom); fclose(urandom); }

    /* nonce_prefix：LE u64（对应 Rust u64::from_le_bytes） */
    for (int j = 0; j < 8; ++j) {
        h_params.nonce_prefix[0] |= (u64)prefix[j]   << (j*8);
        h_params.nonce_prefix[1] |= (u64)prefix[8+j] << (j*8);
    }

    /* 随机起始计数器（128 bit，hi:lo） */
    u8 cb[16] = {0};
    urandom = fopen("/dev/urandom", "rb");
    if (urandom) { fread(cb, 1, 16, urandom); fclose(urandom); }
    u64 counter_hi = 0, counter_lo = 0;
    for (int j = 0; j < 8; ++j) counter_hi = (counter_hi << 8) | cb[j];
    for (int j = 0; j < 8; ++j) counter_lo = (counter_lo << 8) | cb[8+j];

    const int THREADS_PER_BLOCK = 256;
    int blocks = ((int)batch_size + THREADS_PER_BLOCK - 1) / THREADS_PER_BLOCK;

    long long start_ms       = now_ms();
    long long last_progress  = start_ms;
    u64       total_hashes   = 0;

    while (1) {
        h_params.counter_hi = counter_hi;
        h_params.counter_lo = counter_lo;

        CUDA_CHECK(cudaMemcpy(d_params, &h_params,
                              sizeof(Params), cudaMemcpyHostToDevice));

        Result zero = {0, 0, {0,0,0,0}};
        CUDA_CHECK(cudaMemcpy(d_result, &zero,
                              sizeof(Result), cudaMemcpyHostToDevice));

        hash256_search<<<blocks, THREADS_PER_BLOCK>>>(d_params, d_result);
        CUDA_CHECK(cudaGetLastError());
        CUDA_CHECK(cudaDeviceSynchronize());

        total_hashes += (u64)batch_size;

        /* 推进计数器 */
        u64 new_lo = counter_lo + (u64)batch_size;
        if (new_lo < counter_lo) counter_hi++;
        counter_lo = new_lo;

        /* 读取结果 */
        Result h_result;
        CUDA_CHECK(cudaMemcpy(&h_result, d_result,
                              sizeof(Result), cudaMemcpyDeviceToHost));

        if (h_result.found) {
            /* 重建命中时的计数器 */
            u64 hit_lo = h_params.counter_lo + (u64)h_result.gid;
            u64 hit_hi = h_params.counter_hi +
                         (hit_lo < h_params.counter_lo ? 1ULL : 0ULL);

            /* nonce = prefix(16) || counter_BE(16) */
            u8 nonce[32];
            memcpy(nonce, prefix, 16);
            for (int j = 0; j < 8; ++j) nonce[16+j] = (u8)(hit_hi >> (56 - j*8));
            for (int j = 0; j < 8; ++j) nonce[24+j] = (u8)(hit_lo >> (56 - j*8));

            /* digest：大端 u64 → 字节 */
            u8 digest[32];
            for (int i = 0; i < 4; ++i) {
                u64 w = h_result.digest[i];
                for (int j = 0; j < 8; ++j)
                    digest[i*8+j] = (u8)(w >> (56 - j*8));
            }

            char nonce_hex[67], digest_hex[67];
            hex_encode(nonce,  32, nonce_hex);
            hex_encode(digest, 32, digest_hex);

            long long elapsed = now_ms() - start_ms;
            emit_hit(nonce_hex, digest_hex, total_hashes, elapsed);
            emit_stopped(total_hashes, elapsed);

            cudaFree(d_params);
            cudaFree(d_result);
            return 0;
        }

        /* 进度上报 */
        long long now = now_ms();
        if (now - last_progress >= (long long)progress_ms) {
            long long elapsed = now - start_ms;
            double rate = elapsed > 0
                ? (double)total_hashes / ((double)elapsed / 1000.0) : 0.0;
            emit_progress(total_hashes, rate, elapsed);
            last_progress = now;
        }
    }
}
