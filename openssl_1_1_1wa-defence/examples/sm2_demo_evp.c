/*
 * SM2 国密非对称加密算法验证示例 (EVP 公共接口版本)
 *
 * 本版本仅使用 OpenSSL EVP 公共接口，不依赖内部头文件 crypto/sm2.h，
 * 因此可以正常链接 OpenSSL 动态库 (libcrypto.so)。
 *
 * SM2 基于 256 位椭圆曲线，支持：
 *   1. 数字签名 (EVP_DigestSign / EVP_DigestVerify)
 *   2. 公钥加密 (EVP_PKEY_encrypt / EVP_PKEY_decrypt)
 *   3. 密钥交换 (SM2_compute_key - 公共 API)
 *
 */

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/sm2.h>

/* SM2 默认用户 ID (GM/T 0009-2012) - 内部头文件未导出，在此手动定义 */
#define SM2_DEFAULT_USERID     "1234567812345678"
#define SM2_DEFAULT_USERID_LEN 16

/* 打印十六进制数据 */
static void print_hex(const char *label, const unsigned char *data, size_t len)
{
    size_t i;
    printf("%s (%zu bytes):\n  ", label, len);
    for (i = 0; i < len; i++) {
        printf("%02X", data[i]);
        if ((i + 1) % 32 == 0 && i + 1 < len)
            printf("\n  ");
    }
    printf("\n");
}

/* 打印 OpenSSL 错误栈 */
static void print_errors(void)
{
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        fprintf(stderr, "  OpenSSL Error: %s\n", ERR_error_string(err, NULL));
    }
}

/*
 * 通过 EVP_PKEY 生成 SM2 密钥对
 * 使用 EVP_PKEY_CTX 方式，完全走公共接口
 */
static EVP_PKEY *generate_sm2_pkey(void)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *params = NULL;
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *pkey = NULL;

    /* 第一步: 生成 SM2 曲线参数 */
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

    /* 第二步: 基于参数生成密钥对 */
    kctx = EVP_PKEY_CTX_new(params, NULL);
    if (kctx == NULL)
        goto err;

    if (EVP_PKEY_keygen_init(kctx) != 1)
        goto err;

    if (EVP_PKEY_keygen(kctx, &pkey) != 1)
        goto err;

    /* 第三步: 设置 SM2 别名类型 (关键步骤!) */
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

/*
 * 测试1: SM2 密钥生成
 */
static int test_sm2_keygen(void)
{
    EVP_PKEY *pkey = NULL;
    EC_KEY *ec_key = NULL;
    const EC_POINT *pub_key = NULL;
    const BIGNUM *priv_key = NULL;
    const EC_GROUP *group = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *x = NULL, *y = NULL;
    int ret = 0;

    printf("=== 测试1: SM2 密钥对生成 ===\n");

    pkey = generate_sm2_pkey();
    if (pkey == NULL) {
        fprintf(stderr, "错误: 生成 SM2 密钥对失败\n");
        print_errors();
        goto err;
    }

    /* 从 EVP_PKEY 提取 EC_KEY 以打印密钥详情 */
    ec_key = EVP_PKEY_get0_EC_KEY(pkey);
    if (ec_key == NULL) {
        fprintf(stderr, "错误: 获取 EC_KEY 失败\n");
        goto err;
    }

    priv_key = EC_KEY_get0_private_key(ec_key);
    pub_key = EC_KEY_get0_public_key(ec_key);
    group = EC_KEY_get0_group(ec_key);

    if (priv_key == NULL || pub_key == NULL) {
        fprintf(stderr, "错误: 获取密钥失败\n");
        goto err;
    }

    printf("曲线: SM2 (NID=%d)\n", EC_GROUP_get_curve_name(group));
    printf("密钥位数: %d bits\n", EC_GROUP_get_degree(group));

    ctx = BN_CTX_new();
    x = BN_new();
    y = BN_new();
    if (ctx == NULL || x == NULL || y == NULL)
        goto err;

    if (EC_POINT_get_affine_coordinates(group, pub_key, x, y, ctx) != 1)
        goto err;

    {
        char *priv_hex = BN_bn2hex(priv_key);
        char *x_hex = BN_bn2hex(x);
        char *y_hex = BN_bn2hex(y);

        printf("私钥 d:  %s\n", priv_hex);
        printf("公钥 Px: %s\n", x_hex);
        printf("公钥 Py: %s\n", y_hex);

        OPENSSL_free(priv_hex);
        OPENSSL_free(x_hex);
        OPENSSL_free(y_hex);
    }

    if (EC_KEY_check_key(ec_key) == 1) {
        printf("结果: ✓ SM2 密钥对生成并验证通过\n");
        ret = 1;
    } else {
        printf("结果: ✗ SM2 密钥验证失败\n");
    }

err:
    BN_free(x);
    BN_free(y);
    BN_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ret;
}

/*
 * 测试2: SM2 数字签名与验签 (EVP_DigestSign / EVP_DigestVerify)
 *
 * 替代内部函数: sm2_do_sign / sm2_do_verify
 * EVP 调用链: EVP_DigestSignInit → EVP_PKEY_CTX_set1_id →
 *             EVP_DigestSignUpdate → EVP_DigestSignFinal
 * 内部实现: EVP_DigestSign → pkey_sm2_sign → sm2_sign
 *          (自动计算 Z 值: pkey_sm2_digest_custom)
 */
static int test_sm2_sign_verify(void)
{
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    const char *userid = SM2_DEFAULT_USERID;
    const char *message = "Hello, SM2 Digital Signature!";
    unsigned char *sig = NULL;
    size_t sig_len = 0;
    int ret = 0;
    int verify_result;

    printf("\n=== 测试2: SM2 数字签名与验签 (EVP 接口) ===\n");
    printf("User ID: \"%s\"\n", userid);
    printf("消息: \"%s\"\n", message);

    pkey = generate_sm2_pkey();
    if (pkey == NULL)
        goto err;

    /* 签名 */
    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL)
        goto err;

    if (EVP_DigestSignInit(md_ctx, &pctx, EVP_sm3(), NULL, pkey) != 1) {
        fprintf(stderr, "错误: DigestSignInit 失败\n");
        print_errors();
        goto err;
    }

    /* 设置 SM2 用户 ID */
    if (EVP_PKEY_CTX_set1_id(pctx, userid, strlen(userid)) != 1) {
        fprintf(stderr, "错误: 设置 SM2 ID 失败\n");
        print_errors();
        goto err;
    }

    if (EVP_DigestSignUpdate(md_ctx, message, strlen(message)) != 1) {
        fprintf(stderr, "错误: DigestSignUpdate 失败\n");
        goto err;
    }

    /* 获取签名长度 */
    if (EVP_DigestSignFinal(md_ctx, NULL, &sig_len) != 1) {
        fprintf(stderr, "错误: 获取签名长度失败\n");
        goto err;
    }

    sig = OPENSSL_malloc(sig_len);
    if (sig == NULL)
        goto err;

    if (EVP_DigestSignFinal(md_ctx, sig, &sig_len) != 1) {
        fprintf(stderr, "错误: DigestSignFinal 失败\n");
        print_errors();
        goto err;
    }

    print_hex("签名", sig, sig_len);

    /* 验签 */
    EVP_MD_CTX_free(md_ctx);
    md_ctx = EVP_MD_CTX_new();
    pctx = NULL;
    if (md_ctx == NULL)
        goto err;

    if (EVP_DigestVerifyInit(md_ctx, &pctx, EVP_sm3(), NULL, pkey) != 1) {
        fprintf(stderr, "错误: DigestVerifyInit 失败\n");
        goto err;
    }

    if (EVP_PKEY_CTX_set1_id(pctx, userid, strlen(userid)) != 1) {
        fprintf(stderr, "错误: 设置验签 SM2 ID 失败\n");
        goto err;
    }

    if (EVP_DigestVerifyUpdate(md_ctx, message, strlen(message)) != 1) {
        fprintf(stderr, "错误: DigestVerifyUpdate 失败\n");
        goto err;
    }

    verify_result = EVP_DigestVerifyFinal(md_ctx, sig, sig_len);

    if (verify_result == 1) {
        printf("验签: ✓ 通过\n");
    } else {
        printf("验签: ✗ 失败\n");
        goto err;
    }

    /* 篡改消息后验签应失败 */
    {
        const char *tampered = "Hello, SM2 Digital Signature?";
        EVP_MD_CTX_free(md_ctx);
        md_ctx = EVP_MD_CTX_new();
        pctx = NULL;
        if (md_ctx == NULL)
            goto err;

        if (EVP_DigestVerifyInit(md_ctx, &pctx, EVP_sm3(), NULL, pkey) != 1)
            goto err;
        if (EVP_PKEY_CTX_set1_id(pctx, userid, strlen(userid)) != 1)
            goto err;
        if (EVP_DigestVerifyUpdate(md_ctx, tampered, strlen(tampered)) != 1)
            goto err;

        int tamper_result = EVP_DigestVerifyFinal(md_ctx, sig, sig_len);
        if (tamper_result != 1) {
            printf("篡改验签: ✓ 正确拒绝了篡改消息\n");
            ret = 1;
        } else {
            printf("篡改验签: ✗ 错误接受了篡改消息\n");
        }
    }

err:
    OPENSSL_free(sig);
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    return ret;
}

/*
 * 测试3: SM2 公钥加密与解密 (EVP_PKEY_encrypt / EVP_PKEY_decrypt)
 *
 * 替代内部函数: sm2_encrypt / sm2_decrypt / sm2_ciphertext_size / sm2_plaintext_size
 * EVP 调用链: EVP_PKEY_CTX_new → EVP_PKEY_encrypt_init →
 *             EVP_PKEY_encrypt(out=NULL, &len, in, inlen) → 获取密文长度
 *             EVP_PKEY_encrypt(out, &len, in, inlen) → 加密
 * 内部实现: EVP_PKEY_encrypt → pkey_sm2_encrypt → sm2_encrypt
 *          out=NULL 时自动调用 sm2_ciphertext_size 获取长度
 */
static int test_sm2_encrypt_decrypt(void)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *cctx = NULL;
    const char *message = "SM2 Encryption Test: GuoMi!";
    size_t msg_len;
    unsigned char *ciphertext = NULL;
    size_t ciphertext_len = 0;
    unsigned char *plaintext = NULL;
    size_t plaintext_len = 0;
    int ret = 0;

    printf("\n=== 测试3: SM2 公钥加密与解密 (EVP 接口) ===\n");
    printf("明文: \"%s\" (%zu bytes)\n", message, strlen(message));

    pkey = generate_sm2_pkey();
    if (pkey == NULL)
        goto err;

    msg_len = strlen(message);

    /* 加密 */
    cctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (cctx == NULL)
        goto err;

    if (EVP_PKEY_encrypt_init(cctx) != 1) {
        fprintf(stderr, "错误: encrypt_init 失败\n");
        print_errors();
        goto err;
    }

    /* 第一步: 获取密文长度 (替代 sm2_ciphertext_size) */
    if (EVP_PKEY_encrypt(cctx, NULL, &ciphertext_len,
                         (const unsigned char *)message, msg_len) != 1) {
        fprintf(stderr, "错误: 获取密文长度失败\n");
        print_errors();
        goto err;
    }

    printf("预计密文长度: %zu bytes\n", ciphertext_len);

    ciphertext = OPENSSL_zalloc(ciphertext_len);
    if (ciphertext == NULL)
        goto err;

    /* 第二步: 执行加密 */
    if (EVP_PKEY_encrypt(cctx, ciphertext, &ciphertext_len,
                         (const unsigned char *)message, msg_len) != 1) {
        fprintf(stderr, "错误: SM2 加密失败\n");
        print_errors();
        goto err;
    }

    print_hex("密文", ciphertext, ciphertext_len);

    /* 解密 */
    EVP_PKEY_CTX_free(cctx);
    cctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (cctx == NULL)
        goto err;

    if (EVP_PKEY_decrypt_init(cctx) != 1) {
        fprintf(stderr, "错误: decrypt_init 失败\n");
        print_errors();
        goto err;
    }

    /* 第一步: 获取明文长度 (替代 sm2_plaintext_size) */
    if (EVP_PKEY_decrypt(cctx, NULL, &plaintext_len,
                         ciphertext, ciphertext_len) != 1) {
        fprintf(stderr, "错误: 获取明文长度失败\n");
        print_errors();
        goto err;
    }

    plaintext = OPENSSL_zalloc(plaintext_len + 1);
    if (plaintext == NULL)
        goto err;

    /* 第二步: 执行解密 */
    if (EVP_PKEY_decrypt(cctx, plaintext, &plaintext_len,
                         ciphertext, ciphertext_len) != 1) {
        fprintf(stderr, "错误: SM2 解密失败\n");
        print_errors();
        goto err;
    }

    plaintext[plaintext_len] = '\0';
    printf("解密: \"%s\" (%zu bytes)\n", plaintext, plaintext_len);

    if (plaintext_len == msg_len &&
        memcmp(plaintext, message, plaintext_len) == 0) {
        printf("结果: ✓ SM2 加解密验证通过\n");
        ret = 1;
    } else {
        printf("结果: ✗ SM2 加解密验证失败\n");
    }

err:
    OPENSSL_free(ciphertext);
    OPENSSL_free(plaintext);
    EVP_PKEY_CTX_free(cctx);
    EVP_PKEY_free(pkey);
    return ret;
}

/*
 * 测试4: SM2 通过 EVP 高层接口进行签名验签 (与测试2相同的 EVP 接口)
 *
 * 此测试演示使用 EVP_PKEY_set_alias_type 方式
 * 与原版 sm2_demo.c 中的 test_sm2_evp_sign() 逻辑一致
 */
static int test_sm2_evp_sign(void)
{
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    const char *message = "EVP-level SM2 signing test!";
    unsigned char *sig = NULL;
    size_t sig_len = 0;
    int ret = 0;

    printf("\n=== 测试4: SM2 EVP 签名接口 (EVP_PKEY_set_alias_type) ===\n");
    printf("消息: \"%s\"\n", message);

    pkey = generate_sm2_pkey();
    if (pkey == NULL)
        goto err;

    /* 签名 */
    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL)
        goto err;

    if (EVP_DigestSignInit(md_ctx, &pctx, EVP_sm3(), NULL, pkey) != 1) {
        fprintf(stderr, "错误: DigestSignInit 失败\n");
        print_errors();
        goto err;
    }

    /* 设置 SM2 ID (不设置时 EVP 内部会自动使用默认 ID) */
    if (EVP_PKEY_CTX_set1_id(pctx, SM2_DEFAULT_USERID, SM2_DEFAULT_USERID_LEN) != 1) {
        fprintf(stderr, "错误: 设置 SM2 ID 失败\n");
        print_errors();
        goto err;
    }

    if (EVP_DigestSignUpdate(md_ctx, message, strlen(message)) != 1) {
        fprintf(stderr, "错误: DigestSignUpdate 失败\n");
        goto err;
    }

    if (EVP_DigestSignFinal(md_ctx, NULL, &sig_len) != 1) {
        fprintf(stderr, "错误: 获取签名长度失败\n");
        goto err;
    }

    sig = OPENSSL_malloc(sig_len);
    if (sig == NULL)
        goto err;

    if (EVP_DigestSignFinal(md_ctx, sig, &sig_len) != 1) {
        fprintf(stderr, "错误: DigestSignFinal 失败\n");
        print_errors();
        goto err;
    }

    print_hex("EVP 签名", sig, sig_len);

    /* 验签 */
    EVP_MD_CTX_free(md_ctx);
    md_ctx = EVP_MD_CTX_new();
    pctx = NULL;
    if (md_ctx == NULL)
        goto err;

    if (EVP_DigestVerifyInit(md_ctx, &pctx, EVP_sm3(), NULL, pkey) != 1) {
        fprintf(stderr, "错误: DigestVerifyInit 失败\n");
        goto err;
    }

    if (EVP_PKEY_CTX_set1_id(pctx, SM2_DEFAULT_USERID, SM2_DEFAULT_USERID_LEN) != 1) {
        fprintf(stderr, "错误: 设置验签 SM2 ID 失败\n");
        goto err;
    }

    if (EVP_DigestVerifyUpdate(md_ctx, message, strlen(message)) != 1) {
        fprintf(stderr, "错误: DigestVerifyUpdate 失败\n");
        goto err;
    }

    if (EVP_DigestVerifyFinal(md_ctx, sig, sig_len) == 1) {
        printf("EVP 验签: ✓ 通过\n");
        ret = 1;
    } else {
        printf("EVP 验签: ✗ 失败\n");
        print_errors();
    }

err:
    OPENSSL_free(sig);
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    return ret;
}

/*
 * 测试5: SM2 密钥交换 (KEP)
 *
 * SM2_compute_key 是 openssl/sm2.h 中导出的公共 API，
 * 不需要内部头文件 crypto/sm2.h，可以正常链接动态库。
 *
 * 注意: SM2 KEP 没有对应的 EVP_PKEY_derive 接口，
 * 只能通过 SM2_compute_key 公共函数调用。
 */
static int test_sm2_key_exchange(void)
{
    EVP_PKEY *alice_pkey = NULL;
    EVP_PKEY *alice_ecdhe_pkey = NULL;
    EVP_PKEY *bob_pkey = NULL;
    EVP_PKEY *bob_ecdhe_pkey = NULL;
    EC_KEY *alice_key = NULL;
    EC_KEY *alice_ecdhe = NULL;
    EC_KEY *bob_key = NULL;
    EC_KEY *bob_ecdhe = NULL;
    const char *alice_id = "alice@example.com";
    const char *bob_id = "bob@example.com";
    unsigned char alice_shared[32];
    unsigned char bob_shared[32];
    int alice_ret, bob_ret;
    int ret = 0;

    printf("\n=== 测试5: SM2 密钥交换 (KEP) ===\n");
    printf("Alice ID: \"%s\"\n", alice_id);
    printf("Bob   ID: \"%s\"\n", bob_id);

    /* 生成双方密钥 (通过 EVP 生成后提取 EC_KEY) */
    alice_pkey = generate_sm2_pkey();
    alice_ecdhe_pkey = generate_sm2_pkey();
    bob_pkey = generate_sm2_pkey();
    bob_ecdhe_pkey = generate_sm2_pkey();

    if (!alice_pkey || !alice_ecdhe_pkey || !bob_pkey || !bob_ecdhe_pkey) {
        fprintf(stderr, "错误: 密钥生成失败\n");
        goto err;
    }

    /* 从 EVP_PKEY 提取 EC_KEY (SM2_compute_key 需要 EC_KEY 参数) */
    alice_key = EVP_PKEY_get0_EC_KEY(alice_pkey);
    alice_ecdhe = EVP_PKEY_get0_EC_KEY(alice_ecdhe_pkey);
    bob_key = EVP_PKEY_get0_EC_KEY(bob_pkey);
    bob_ecdhe = EVP_PKEY_get0_EC_KEY(bob_ecdhe_pkey);

    if (!alice_key || !alice_ecdhe || !bob_key || !bob_ecdhe) {
        fprintf(stderr, "错误: 提取 EC_KEY 失败\n");
        goto err;
    }

    printf("密钥长度: 32 bytes (256 bits)\n");

    /* Alice 计算共享密钥 (Alice 是发起方 server=1) */
    alice_ret = SM2_compute_key(alice_shared, sizeof(alice_shared),
                                1,  /* server (initiator) */
                                bob_id, (int)strlen(bob_id),
                                alice_id, (int)strlen(alice_id),
                                bob_ecdhe, alice_ecdhe,
                                bob_key, alice_key,
                                EVP_sm3());

    if (alice_ret != sizeof(alice_shared)) {
        fprintf(stderr, "错误: Alice 密钥协商失败 (ret=%d)\n", alice_ret);
        print_errors();
        goto err;
    }

    /* Bob 计算共享密钥 (Bob 是响应方 server=0) */
    bob_ret = SM2_compute_key(bob_shared, sizeof(bob_shared),
                              0,  /* client (responder) */
                              alice_id, (int)strlen(alice_id),
                              bob_id, (int)strlen(bob_id),
                              alice_ecdhe, bob_ecdhe,
                              alice_key, bob_key,
                              EVP_sm3());

    if (bob_ret != sizeof(bob_shared)) {
        fprintf(stderr, "错误: Bob 密钥协商失败 (ret=%d)\n", bob_ret);
        print_errors();
        goto err;
    }

    print_hex("Alice 共享密钥", alice_shared, sizeof(alice_shared));
    print_hex("Bob   共享密钥", bob_shared, sizeof(bob_shared));

    if (memcmp(alice_shared, bob_shared, sizeof(alice_shared)) == 0) {
        printf("结果: ✓ 双方协商的共享密钥一致！SM2 KEP 验证通过\n");
        ret = 1;
    } else {
        printf("结果: ✗ 双方共享密钥不一致\n");
    }

err:
    EVP_PKEY_free(alice_pkey);
    EVP_PKEY_free(alice_ecdhe_pkey);
    EVP_PKEY_free(bob_pkey);
    EVP_PKEY_free(bob_ecdhe_pkey);
    /* EC_KEY 由 EVP_PKEY 管理，不需要单独释放 */
    return ret;
}

int main(void)
{
    int passed = 0, total = 5;

    printf("╔════════════════════════════════════════════╗\n");
    printf("║  SM2 国密非对称加密算法验证程序 (EVP 版)   ║\n");
    printf("║  GM/T 0003-2012 / GM/T 0009-2012           ║\n");
    printf("║  仅使用 EVP 公共接口，可链接动态库          ║\n");
    printf("╚══════════════════════════════════════════════╝\n\n");

    passed += test_sm2_keygen();
    passed += test_sm2_sign_verify();
    passed += test_sm2_encrypt_decrypt();
    passed += test_sm2_evp_sign();
    passed += test_sm2_key_exchange();

    printf("\n══════════════════════════════════════════════\n");
    printf("SM2 测试结果: %d/%d 通过\n", passed, total);
    printf("══════════════════════════════════════════════\n");

    return (passed == total) ? 0 : 1;
}
