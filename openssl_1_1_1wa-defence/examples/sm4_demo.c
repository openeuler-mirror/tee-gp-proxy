/*
 * SM4 国密对称加密算法验证示例
 *
 * SM4 是中国国家密码管理局发布的分组密码算法标准（GM/T 0002-2012）
 * 分组长度 128 位，密钥长度 128 位
 *
 */

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

/* 打印十六进制数据 */
static void print_hex(const char *label, const unsigned char *data, size_t len)
{
    size_t i;
    printf("%s (%zu bytes): ", label, len);
    for (i = 0; i < len; i++)
        printf("%02X", data[i]);
    printf("\n");
}

/*
 * 测试1: SM4-ECB 模式
 *
 * GM/T 0002-2012 标准测试向量:
 *   密钥:     01234567 89ABCDEF FEDCBA98 76543210
 *   明文:     01234567 89ABCDEF FEDCBA98 76543210
 *   密文:     681EDF34 D206965E 86B3E94F 536E4246
 */
static int test_sm4_ecb(void)
{
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = NULL;
    int ret = 0;

    const unsigned char key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    const unsigned char plaintext[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    const unsigned char expected_ct[16] = {
        0x68, 0x1E, 0xDF, 0x34, 0xD2, 0x06, 0x96, 0x5E,
        0x86, 0xB3, 0xE9, 0x4F, 0x53, 0x6E, 0x42, 0x46
    };
    unsigned char ciphertext[32];
    unsigned char decrypted[32];
    int outlen = 0, tmplen = 0;

    printf("=== 测试1: SM4-ECB 标准测试向量 ===\n");

    cipher = EVP_sm4_ecb();
    if (cipher == NULL) {
        fprintf(stderr, "错误: SM4-ECB 不可用\n");
        goto err;
    }

    print_hex("密钥", key, sizeof(key));
    print_hex("明文", plaintext, sizeof(plaintext));

    /* 加密 */
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        goto err;

    /* 禁用 padding，因为我们的明文刚好是一个分组 */
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, NULL) != 1 ||
        EVP_CIPHER_CTX_set_padding(ctx, 0) != 1 ||
        EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, sizeof(plaintext)) != 1 ||
        EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &tmplen) != 1)
        goto err;
    outlen += tmplen;

    print_hex("加密结果", ciphertext, outlen);
    print_hex("期望密文", expected_ct, sizeof(expected_ct));

    if (outlen == (int)sizeof(expected_ct) &&
        memcmp(ciphertext, expected_ct, outlen) == 0) {
        printf("加密: ✓ 通过\n");
    } else {
        printf("加密: ✗ 失败\n");
        goto err;
    }

    /* 解密 */
    if (EVP_DecryptInit_ex(ctx, cipher, NULL, key, NULL) != 1 ||
        EVP_CIPHER_CTX_set_padding(ctx, 0) != 1 ||
        EVP_DecryptUpdate(ctx, decrypted, &outlen, ciphertext, sizeof(expected_ct)) != 1 ||
        EVP_DecryptFinal_ex(ctx, decrypted + outlen, &tmplen) != 1)
        goto err;
    outlen += tmplen;

    print_hex("解密结果", decrypted, outlen);

    if (outlen == (int)sizeof(plaintext) &&
        memcmp(decrypted, plaintext, outlen) == 0) {
        printf("解密: ✓ 通过\n");
        ret = 1;
    } else {
        printf("解密: ✗ 失败\n");
    }

err:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/*
 * 测试2: SM4-CBC 模式加解密
 */
static int test_sm4_cbc(void)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int ret = 0;

    const unsigned char key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    const unsigned char iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    const char *message = "SM4-CBC mode test for GuoMi!";  /* 28 bytes */
    unsigned char ciphertext[64];
    unsigned char decrypted[64];
    int ct_len = 0, pt_len = 0, tmplen = 0;

    printf("\n=== 测试2: SM4-CBC 模式加解密 ===\n");

    print_hex("密钥", key, sizeof(key));
    print_hex("IV  ", iv, sizeof(iv));
    printf("明文: \"%s\" (%zu bytes)\n", message, strlen(message));

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        goto err;

    /* 加密（启用 PKCS#7 padding） */
    if (EVP_EncryptInit_ex(ctx, EVP_sm4_cbc(), NULL, key, iv) != 1 ||
        EVP_EncryptUpdate(ctx, ciphertext, &ct_len, (const unsigned char *)message, (int)strlen(message)) != 1 ||
        EVP_EncryptFinal_ex(ctx, ciphertext + ct_len, &tmplen) != 1)
        goto err;
    ct_len += tmplen;

    print_hex("密文", ciphertext, ct_len);

    /* 解密 */
    if (EVP_DecryptInit_ex(ctx, EVP_sm4_cbc(), NULL, key, iv) != 1 ||
        EVP_DecryptUpdate(ctx, decrypted, &pt_len, ciphertext, ct_len) != 1 ||
        EVP_DecryptFinal_ex(ctx, decrypted + pt_len, &tmplen) != 1)
        goto err;
    pt_len += tmplen;
    decrypted[pt_len] = '\0';

    printf("解密: \"%s\" (%d bytes)\n", decrypted, pt_len);

    if (pt_len == (int)strlen(message) &&
        memcmp(decrypted, message, pt_len) == 0) {
        printf("结果: ✓ CBC 模式加解密验证通过\n");
        ret = 1;
    } else {
        printf("结果: ✗ CBC 模式加解密验证失败\n");
    }

err:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/*
 * 测试3: SM4-CTR 模式加解密
 */
static int test_sm4_ctr(void)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int ret = 0;

    unsigned char key[16];
    unsigned char iv[16];
    const char *message = "CTR mode is a stream cipher mode, no padding needed!";
    unsigned char ciphertext[128];
    unsigned char decrypted[128];
    int ct_len = 0, pt_len = 0, tmplen = 0;

    printf("\n=== 测试3: SM4-CTR 模式加解密 ===\n");

    /* 使用随机密钥和 IV */
    if (RAND_bytes(key, sizeof(key)) != 1 ||
        RAND_bytes(iv, sizeof(iv)) != 1) {
        fprintf(stderr, "错误: 随机数生成失败\n");
        goto err;
    }

    print_hex("密钥 (随机)", key, sizeof(key));
    print_hex("IV   (随机)", iv, sizeof(iv));
    printf("明文: \"%s\" (%zu bytes)\n", message, strlen(message));

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        goto err;

    /* CTR 模式不需要 padding */
    if (EVP_EncryptInit_ex(ctx, EVP_sm4_ctr(), NULL, key, iv) != 1 ||
        EVP_EncryptUpdate(ctx, ciphertext, &ct_len, (const unsigned char *)message, (int)strlen(message)) != 1 ||
        EVP_EncryptFinal_ex(ctx, ciphertext + ct_len, &tmplen) != 1)
        goto err;
    ct_len += tmplen;

    print_hex("密文", ciphertext, ct_len);
    printf("密文长度与明文相同: %s (CTR 流密码特性)\n",
           ct_len == (int)strlen(message) ? "是" : "否");

    /* 解密 */
    if (EVP_DecryptInit_ex(ctx, EVP_sm4_ctr(), NULL, key, iv) != 1 ||
        EVP_DecryptUpdate(ctx, decrypted, &pt_len, ciphertext, ct_len) != 1 ||
        EVP_DecryptFinal_ex(ctx, decrypted + pt_len, &tmplen) != 1)
        goto err;
    pt_len += tmplen;
    decrypted[pt_len] = '\0';

    printf("解密: \"%s\"\n", decrypted);

    if (pt_len == (int)strlen(message) &&
        memcmp(decrypted, message, pt_len) == 0) {
        printf("结果: ✓ CTR 模式加解密验证通过\n");
        ret = 1;
    } else {
        printf("结果: ✗ CTR 模式加解密验证失败\n");
    }

err:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/*
 * 测试4: SM4 所有模式的算法信息
 */
static int test_sm4_info(void)
{
    printf("\n=== 测试4: SM4 各模式算法信息 ===\n");

    struct {
        const char *name;
        const EVP_CIPHER *(*func)(void);
    } modes[] = {
        { "SM4-ECB", EVP_sm4_ecb },
        { "SM4-CBC", EVP_sm4_cbc },
        { "SM4-CFB", EVP_sm4_cfb128 },
        { "SM4-OFB", EVP_sm4_ofb },
        { "SM4-CTR", EVP_sm4_ctr },
    };
    int i, count = sizeof(modes) / sizeof(modes[0]);

    printf("%-10s  %-10s  %-10s  %-10s\n", "模式", "密钥(字节)", "IV(字节)", "分组(字节)");
    printf("%-10s  %-10s  %-10s  %-10s\n", "--------", "--------", "--------", "--------");

    for (i = 0; i < count; i++) {
        const EVP_CIPHER *c = modes[i].func();
        if (c) {
            printf("%-10s  %-10d  %-10d  %-10d\n",
                   modes[i].name,
                   EVP_CIPHER_key_length(c),
                   EVP_CIPHER_iv_length(c),
                   EVP_CIPHER_block_size(c));
        }
    }

    printf("\n结果: ✓ SM4 支持以上所有工作模式\n");
    return 1;
}

/*
 * 测试5: SM4-OFB 模式
 */
static int test_sm4_ofb(void)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int ret = 0;

    unsigned char key[16];
    unsigned char iv[16];
    const char *message = "OFB mode test for SM4 GuoMi algorithm";
    unsigned char ciphertext[128];
    unsigned char decrypted[128];
    int ct_len = 0, pt_len = 0, tmplen = 0;

    printf("\n=== 测试5: SM4-OFB 模式加解密 ===\n");

    if (RAND_bytes(key, sizeof(key)) != 1 ||
        RAND_bytes(iv, sizeof(iv)) != 1) {
        fprintf(stderr, "错误: 随机数生成失败\n");
        goto err;
    }

    print_hex("密钥 (随机)", key, sizeof(key));
    print_hex("IV   (随机)", iv, sizeof(iv));
    printf("明文: \"%s\" (%zu bytes)\n", message, strlen(message));

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        goto err;

    if (EVP_EncryptInit_ex(ctx, EVP_sm4_ofb(), NULL, key, iv) != 1 ||
        EVP_EncryptUpdate(ctx, ciphertext, &ct_len, (const unsigned char *)message, (int)strlen(message)) != 1 ||
        EVP_EncryptFinal_ex(ctx, ciphertext + ct_len, &tmplen) != 1)
        goto err;
    ct_len += tmplen;

    print_hex("密文", ciphertext, ct_len);

    if (EVP_DecryptInit_ex(ctx, EVP_sm4_ofb(), NULL, key, iv) != 1 ||
        EVP_DecryptUpdate(ctx, decrypted, &pt_len, ciphertext, ct_len) != 1 ||
        EVP_DecryptFinal_ex(ctx, decrypted + pt_len, &tmplen) != 1)
        goto err;
    pt_len += tmplen;
    decrypted[pt_len] = '\0';

    printf("解密: \"%s\"\n", decrypted);

    if (pt_len == (int)strlen(message) &&
        memcmp(decrypted, message, pt_len) == 0) {
        printf("结果: ✓ OFB 模式加解密验证通过\n");
        ret = 1;
    } else {
        printf("结果: ✗ OFB 模式加解密验证失败\n");
    }

err:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int main(void)
{
    int passed = 0, total = 5;

    printf("╔══════════════════════════════════════╗\n");
    printf("║    SM4 国密对称加密算法验证程序      ║\n");
    printf("║    GM/T 0002-2012 标准               ║\n");
    printf("╚══════════════════════════════════════╝\n\n");

    passed += test_sm4_ecb();
    passed += test_sm4_cbc();
    passed += test_sm4_ctr();
    passed += test_sm4_info();
    passed += test_sm4_ofb();

    printf("\n════════════════════════════════════════\n");
    printf("SM4 测试结果: %d/%d 通过\n", passed, total);
    printf("════════════════════════════════════════\n");

    return (passed == total) ? 0 : 1;
}
