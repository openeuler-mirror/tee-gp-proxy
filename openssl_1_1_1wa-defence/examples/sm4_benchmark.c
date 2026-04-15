/*
 * SM4 性能基准测试程序
 *
 * 用于测试SM4加密性能
 * 测试项目：
 *   1. SM4-CBC 加密性能
 *
 * 禁用硬件加速运行方式:
 *   OPENSSL_armcap=0 ./sm4_benchmark [iterations]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <sys/time.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

/* 默认迭代次数 */
#define DEFAULT_ITERATIONS 100

/* SM4 测试数据大小 (1KB) */
#define SM4_TEST_DATA_SIZE 1024

/* 获取当前时间（微秒） */
static double get_time_us(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000.0 + tv.tv_usec;
}

/* 单次SM4加密测试，返回耗时（微秒） */
static double benchmark_single_sm4_encrypt(EVP_CIPHER_CTX *ctx,
                                           const unsigned char *plaintext, size_t plaintext_len,
                                           unsigned char *ciphertext, int *ciphertext_len)
{
    double start, end, elapsed;
    int outlen = 0, tmplen = 0;

    start = get_time_us();

    if (EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, plaintext_len) != 1)
        return -1.0;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &tmplen) != 1)
        return -1.0;

    end = get_time_us();
    elapsed = end - start;

    *ciphertext_len = outlen + tmplen;
    return elapsed;
}

/* 计算统计数据 */
typedef struct {
    double min;
    double max;
    double sum;
    double sum_sq;
    int count;
    double mean;
    double variance;
    double std_dev;
} Stats;

static void init_stats(Stats *s)
{
    s->min = 1e20;
    s->max = 0;
    s->sum = 0;
    s->sum_sq = 0;
    s->count = 0;
    s->mean = 0;
    s->variance = 0;
    s->std_dev = 0;
}

static void update_stats(Stats *s, double value)
{
    if (value < s->min) s->min = value;
    if (value > s->max) s->max = value;
    s->sum += value;
    s->sum_sq += value * value;
    s->count++;
}

static void finalize_stats(Stats *s)
{
    if (s->count > 0) {
        s->mean = s->sum / s->count;
        if (s->count > 1) {
            s->variance = (s->sum_sq - s->sum * s->sum / s->count) / (s->count - 1);
            s->std_dev = sqrt(s->variance);
        }
    }
}

static void print_stats(const char *label, Stats *s)
{
    printf("  %s:\n", label);
    printf("    迭代次数: %d\n", s->count);
    printf("    平均值:   %.2f us\n", s->mean);
    printf("    最小值:   %.2f us\n", s->min);
    printf("    最大值:   %.2f us\n", s->max);
    printf("    方差:     %.2f us^2\n", s->variance);
    printf("    标准差:   %.2f us\n", s->std_dev);
    printf("    相对标准偏差: %.2f%%\n", s->mean > 0 ? (s->std_dev / s->mean * 100) : 0);
}

int main(int argc, char *argv[])
{
    int iterations = DEFAULT_ITERATIONS;
    unsigned char sm4_key[16];
    unsigned char sm4_iv[16];
    unsigned char *sm4_plaintext = NULL;
    unsigned char *sm4_ciphertext = NULL;
    int sm4_ct_len = 0;
    EVP_CIPHER_CTX *sm4_ctx = NULL;
    Stats encrypt_stats;
    int i;
    double elapsed;

    if (argc > 1) {
        iterations = atoi(argv[1]);
        if (iterations <= 0) {
            fprintf(stderr, "用法: %s [iterations]\n", argv[0]);
            return 1;
        }
    }

    printf("╔════════════════════════════════════════════════════════╗\n");
    printf("║              SM4 性能基准测试                          ║\n");
    printf("╚════════════════════════════════════════════════════════╝\n\n");

    printf("配置:\n");
    printf("  迭代次数: %d\n", iterations);
    printf("  数据大小: %d bytes\n", SM4_TEST_DATA_SIZE);
    printf("  加密模式: CBC\n");
    printf("\n");

    /* 初始化统计数据 */
    init_stats(&encrypt_stats);

    /* 生成 SM4 密钥和 IV */
    printf("正在生成 SM4 密钥和 IV...\n");
    if (RAND_bytes(sm4_key, sizeof(sm4_key)) != 1 ||
        RAND_bytes(sm4_iv, sizeof(sm4_iv)) != 1) {
        fprintf(stderr, "错误: SM4 密钥生成失败\n");
        return 1;
    }
    printf("SM4 密钥和 IV 生成完成\n\n");

    /* 准备 SM4 测试数据 */
    sm4_plaintext = OPENSSL_malloc(SM4_TEST_DATA_SIZE);
    sm4_ciphertext = OPENSSL_malloc(SM4_TEST_DATA_SIZE + 16); /* 额外空间用于 padding */
    if (sm4_plaintext == NULL || sm4_ciphertext == NULL) {
        fprintf(stderr, "错误: SM4 内存分配失败\n");
        OPENSSL_free(sm4_plaintext);
        OPENSSL_free(sm4_ciphertext);
        return 1;
    }

    /* 用随机数据填充 SM4 测试数据 */
    if (RAND_bytes(sm4_plaintext, SM4_TEST_DATA_SIZE) != 1) {
        fprintf(stderr, "错误: SM4 测试数据生成失败\n");
        OPENSSL_free(sm4_plaintext);
        OPENSSL_free(sm4_ciphertext);
        return 1;
    }

    /* 创建 SM4 加密上下文 */
    sm4_ctx = EVP_CIPHER_CTX_new();
    if (sm4_ctx == NULL) {
        fprintf(stderr, "错误: SM4 上下文创建失败\n");
        OPENSSL_free(sm4_plaintext);
        OPENSSL_free(sm4_ciphertext);
        return 1;
    }

    if (EVP_EncryptInit_ex(sm4_ctx, EVP_sm4_cbc(), NULL, sm4_key, sm4_iv) != 1) {
        fprintf(stderr, "错误: SM4 初始化失败\n");
        OPENSSL_free(sm4_plaintext);
        OPENSSL_free(sm4_ciphertext);
        EVP_CIPHER_CTX_free(sm4_ctx);
        return 1;
    }

    /* 预热运行 */
    printf("预热运行 (10次)...\n");
    for (i = 0; i < 10; i++) {
        benchmark_single_sm4_encrypt(sm4_ctx, sm4_plaintext, SM4_TEST_DATA_SIZE,
                                     sm4_ciphertext, &sm4_ct_len);
    }
    printf("预热完成\n\n");

    /* SM4 加密性能测试 */
    printf("=== SM4 加密性能测试 ===\n");
    for (i = 0; i < iterations; i++) {
        elapsed = benchmark_single_sm4_encrypt(sm4_ctx, sm4_plaintext, SM4_TEST_DATA_SIZE,
                                               sm4_ciphertext, &sm4_ct_len);
        if (elapsed < 0) {
            fprintf(stderr, "错误: SM4 加密测试失败于第 %d 次迭代\n", i + 1);
            continue;
        }
        update_stats(&encrypt_stats, elapsed);

        if ((i + 1) % (iterations / 10 == 0 ? 1 : iterations / 10) == 0) {
            printf("  进度: %d/%d (%.1f%%)\n", i + 1, iterations, (i + 1) * 100.0 / iterations);
        }
    }
    finalize_stats(&encrypt_stats);
    print_stats("SM4加密", &encrypt_stats);

    /* 计算吞吐量 */
    if (encrypt_stats.mean > 0) {
        double throughput = (SM4_TEST_DATA_SIZE / 1024.0) / (encrypt_stats.mean / 1000000.0);
        printf("    吞吐量:   %.2f KB/s\n", throughput);
    }
    printf("\n");

    /* 输出汇总数据（便于脚本解析） */
    printf("════════════════════════════════════════════════════════\n");
    printf("CSV 格式输出 (便于复制到电子表格):\n");
    printf("operation,iterations,mean_us,min_us,max_us,variance_us2,std_dev_us,rsv_percent\n");
    printf("sm4_encrypt,%d,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f\n",
           encrypt_stats.count, encrypt_stats.mean, encrypt_stats.min, encrypt_stats.max,
           encrypt_stats.variance, encrypt_stats.std_dev,
           encrypt_stats.mean > 0 ? (encrypt_stats.std_dev / encrypt_stats.mean * 100) : 0);
    printf("════════════════════════════════════════════════════════\n");

    /* 清理 */
    OPENSSL_free(sm4_plaintext);
    OPENSSL_free(sm4_ciphertext);
    EVP_CIPHER_CTX_free(sm4_ctx);

    return 0;
}
