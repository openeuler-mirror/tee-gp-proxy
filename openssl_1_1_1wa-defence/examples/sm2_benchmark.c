/*
 * SM2 性能基准测试程序
 *
 * 用于对比侧信道防护前后的性能差异
 * 测试项目：
 *   1. SM2 签名性能
 *   2. SM2 解密性能
 *
 * 运行方式:
 *    ./sm2_benchmark [iterations]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <sys/time.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sm2.h>

/* SM2 默认用户 ID */
#define SM2_DEFAULT_USERID     "1234567812345678"
#define SM2_DEFAULT_USERID_LEN 16

/* 默认迭代次数 */
#define DEFAULT_ITERATIONS 100

/* 获取当前时间（微秒） */
static double get_time_us(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000.0 + tv.tv_usec;
}

/* 生成 SM2 密钥对 */
static EVP_PKEY *generate_sm2_pkey(void)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *params = NULL;
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *pkey = NULL;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (pctx == NULL)
        goto err;

    if (EVP_PKEY_paramgen_init(pctx) != 1)
        goto err;

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_sm2) != 1)
        goto err;

    if (EVP_PKEY_paramgen(pctx, &params) != 1)
        goto err;

    EVP_PKEY_CTX_free(pctx);
    pctx = NULL;

    kctx = EVP_PKEY_CTX_new(params, NULL);
    if (kctx == NULL)
        goto err;

    if (EVP_PKEY_keygen_init(kctx) != 1)
        goto err;

    if (EVP_PKEY_keygen(kctx, &pkey) != 1)
        goto err;

    if (EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2) != 1) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
        goto err;
    }

err:
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(params);
    return pkey;
}

/* 单次签名测试，返回耗时（微秒） */
static double benchmark_single_sign(EVP_PKEY *pkey, const unsigned char *msg, size_t msg_len)
{
    EVP_MD_CTX *md_ctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char *sig = NULL;
    size_t sig_len = 0;
    double start, end, elapsed;

    start = get_time_us();

    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL)
        goto err;

    if (EVP_DigestSignInit(md_ctx, &pctx, EVP_sm3(), NULL, pkey) != 1)
        goto err;

    if (EVP_PKEY_CTX_set1_id(pctx, SM2_DEFAULT_USERID, SM2_DEFAULT_USERID_LEN) != 1)
        goto err;

    if (EVP_DigestSignUpdate(md_ctx, msg, msg_len) != 1)
        goto err;

    if (EVP_DigestSignFinal(md_ctx, NULL, &sig_len) != 1)
        goto err;

    sig = OPENSSL_malloc(sig_len);
    if (sig == NULL)
        goto err;

    if (EVP_DigestSignFinal(md_ctx, sig, &sig_len) != 1)
        goto err;

    end = get_time_us();
    elapsed = end - start;

    OPENSSL_free(sig);
    EVP_MD_CTX_free(md_ctx);
    return elapsed;

err:
    OPENSSL_free(sig);
    EVP_MD_CTX_free(md_ctx);
    return -1.0;
}

/* 单次解密测试，返回耗时（微秒） */
static double benchmark_single_decrypt(EVP_PKEY *pkey,
                                       const unsigned char *ciphertext, size_t ciphertext_len,
                                       unsigned char *plaintext, size_t *plaintext_len)
{
    EVP_PKEY_CTX *cctx = NULL;
    double start, end, elapsed;

    start = get_time_us();

    cctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (cctx == NULL)
        goto err;

    if (EVP_PKEY_decrypt_init(cctx) != 1)
        goto err;

    if (EVP_PKEY_decrypt(cctx, plaintext, plaintext_len, ciphertext, ciphertext_len) != 1)
        goto err;

    end = get_time_us();
    elapsed = end - start;

    EVP_PKEY_CTX_free(cctx);
    return elapsed;

err:
    EVP_PKEY_CTX_free(cctx);
    return -1.0;
}

/* 单次加密测试，返回密文 */
static int encrypt_message(EVP_PKEY *pkey,
                           const unsigned char *msg, size_t msg_len,
                           unsigned char **ciphertext, size_t *ciphertext_len)
{
    EVP_PKEY_CTX *cctx = NULL;

    cctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (cctx == NULL)
        goto err;

    if (EVP_PKEY_encrypt_init(cctx) != 1)
        goto err;

    if (EVP_PKEY_encrypt(cctx, NULL, ciphertext_len, msg, msg_len) != 1)
        goto err;

    *ciphertext = OPENSSL_malloc(*ciphertext_len);
    if (*ciphertext == NULL)
        goto err;

    if (EVP_PKEY_encrypt(cctx, *ciphertext, ciphertext_len, msg, msg_len) != 1)
        goto err;

    EVP_PKEY_CTX_free(cctx);
    return 1;

err:
    EVP_PKEY_CTX_free(cctx);
    return 0;
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
    EVP_PKEY *pkey = NULL;
    const char *message = "SM2 Performance Benchmark Test Message for Side-Channel Protection Analysis";
    size_t msg_len;
    unsigned char *ciphertext = NULL;
    size_t ciphertext_len = 0;
    unsigned char *plaintext = NULL;
    size_t plaintext_len = 0;
    Stats sign_stats, decrypt_stats;
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
    printf("║         SM2 性能基准测试 - 侧信道防护对比              ║\n");
    printf("╚════════════════════════════════════════════════════════╝\n\n");

    printf("配置:\n");
    printf("  迭代次数: %d\n", iterations);
    printf("  测试消息: \"%s\" (%zu bytes)\n\n", message, strlen(message));

    /* 初始化统计数据 */
    init_stats(&sign_stats);
    init_stats(&decrypt_stats);

    /* 生成密钥对 */
    printf("正在生成 SM2 密钥对...\n");
    pkey = generate_sm2_pkey();
    if (pkey == NULL) {
        fprintf(stderr, "错误: 密钥生成失败\n");
        return 1;
    }
    printf("密钥对生成完成\n\n");

    msg_len = strlen(message);

    /* 预先加密消息，用于解密测试 */
    if (!encrypt_message(pkey, (const unsigned char *)message, msg_len, &ciphertext, &ciphertext_len)) {
        fprintf(stderr, "错误: 预加密失败\n");
        EVP_PKEY_free(pkey);
        return 1;
    }

    plaintext = OPENSSL_malloc(msg_len + 256);
    if (plaintext == NULL) {
        EVP_PKEY_free(pkey);
        OPENSSL_free(ciphertext);
        return 1;
    }

    /* 预热运行 */
    printf("预热运行 (10次)...\n");
    for (i = 0; i < 10; i++) {
        benchmark_single_sign(pkey, (const unsigned char *)message, msg_len);
        plaintext_len = msg_len + 256;
        benchmark_single_decrypt(pkey, ciphertext, ciphertext_len, plaintext, &plaintext_len);
    }
    printf("预热完成\n\n");

    /* 签名性能测试 */
    printf("=== SM2 签名性能测试 ===\n");
    for (i = 0; i < iterations; i++) {
        elapsed = benchmark_single_sign(pkey, (const unsigned char *)message, msg_len);
        if (elapsed < 0) {
            fprintf(stderr, "错误: 签名测试失败于第 %d 次迭代\n", i + 1);
            continue;
        }
        update_stats(&sign_stats, elapsed);

        if ((i + 1) % (iterations / 10 == 0 ? 1 : iterations / 10) == 0) {
            printf("  进度: %d/%d (%.1f%%)\n", i + 1, iterations, (i + 1) * 100.0 / iterations);
        }
    }
    finalize_stats(&sign_stats);
    print_stats("签名", &sign_stats);
    printf("\n");

    /* 解密性能测试 */
    printf("=== SM2 解密性能测试 ===\n");
    for (i = 0; i < iterations; i++) {
        plaintext_len = msg_len + 256;
        elapsed = benchmark_single_decrypt(pkey, ciphertext, ciphertext_len, plaintext, &plaintext_len);
        if (elapsed < 0) {
            fprintf(stderr, "错误: 解密测试失败于第 %d 次迭代\n", i + 1);
            continue;
        }
        update_stats(&decrypt_stats, elapsed);

        if ((i + 1) % (iterations / 10 == 0 ? 1 : iterations / 10) == 0) {
            printf("  进度: %d/%d (%.1f%%)\n", i + 1, iterations, (i + 1) * 100.0 / iterations);
        }
    }
    finalize_stats(&decrypt_stats);
    print_stats("解密", &decrypt_stats);
    printf("\n");

    /* 输出汇总数据（便于脚本解析） */
    printf("════════════════════════════════════════════════════════\n");
    printf("CSV 格式输出 (便于复制到电子表格):\n");
    printf("operation,iterations,mean_us,min_us,max_us,variance_us2,std_dev_us,rsv_percent\n");
    printf("sign,%d,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f\n",
           sign_stats.count, sign_stats.mean, sign_stats.min, sign_stats.max,
           sign_stats.variance, sign_stats.std_dev,
           sign_stats.mean > 0 ? (sign_stats.std_dev / sign_stats.mean * 100) : 0);
    printf("decrypt,%d,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f\n",
           decrypt_stats.count, decrypt_stats.mean, decrypt_stats.min, decrypt_stats.max,
           decrypt_stats.variance, decrypt_stats.std_dev,
           decrypt_stats.mean > 0 ? (decrypt_stats.std_dev / decrypt_stats.mean * 100) : 0);
    printf("════════════════════════════════════════════════════════\n");

    /* 清理 */
    OPENSSL_free(ciphertext);
    OPENSSL_free(plaintext);
    EVP_PKEY_free(pkey);

    return 0;
}
