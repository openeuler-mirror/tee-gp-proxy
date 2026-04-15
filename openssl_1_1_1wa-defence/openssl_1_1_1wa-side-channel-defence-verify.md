## 1. 克隆 OpenSSL 仓库，切换到指定的 tag
```bash
git clone https://gitcode.com/openeuler/openssl.git openssl_1_1_1wa-src
cd openssl_1_1_1wa-src && git checkout OpenSSL_1_1_1wa
```
## 2. 新建测试目录，拷贝测试文件
```bash
mkdir examples && cd examples
# 将测试代码复制到examples目录下
```

# 未添加侧信道防护测试
## 3. 配置 OpenSSL
在 openssl_1_1_1wa-src 目录下执行以下命令进行配置，--prefix指定安装路径，避免影响系统OpenSSL。-fPIC 确保编译出位置无关代码，便于后续链接。
```bash
./config --prefix=$HOME/openssl_1_1_1wa_modified --openssldir=$HOME/openssl_1_1_1wa_modified/ssl shared no-dso -fPIC
```

## 4. 编译
```bash
make -j$(nproc)
```

## 5. 安装到 --prefix 指定的目录
```bash
make install
```

## 6. 编译测试程序
```bash
cd examples

# 功能测试
gcc -o sm2_demo_evp sm2_demo_evp.c \
    -I$HOME/openssl_1_1_1wa_modified/include \
    -I../include -I.. \
    $HOME/openssl_1_1_1wa_modified/lib/libcrypto.so \
    -ldl -lpthread

gcc -o sm4_demo sm4_demo.c \
    -I$HOME/openssl_1_1_1wa_modified/include \
    -I../include -I.. \
    $HOME/openssl_1_1_1wa_modified/lib/libcrypto.so \
    -ldl -lpthread

# 性能测试
gcc -o sm2_benchmark sm2_benchmark.c \
    -I$HOME/openssl_1_1_1wa_modified/include \
    -I../include -I.. \
    $HOME/openssl_1_1_1wa_modified/lib/libcrypto.so \
    -ldl -lpthread -lm

gcc -o sm4_benchmark sm4_benchmark.c \
    -I$HOME/openssl_1_1_1wa_modified/include \
    -I../include -I.. \
    $HOME/openssl_1_1_1wa_modified/lib/libcrypto.so \
    -ldl -lpthread -lm
```

## 7. 运行测试程序
```bash
export LD_LIBRARY_PATH=$HOME/openssl_1_1_1wa_modified/lib:$LD_LIBRARY_PATH
./sm2_demo_evp
OPENSSL_armcap=0 ./sm4_demo # sm4算法有硬件加速，取消硬件加速

./sm2_benchmark 10000
OPENSSL_armcap=0 ./sm4_benchmark 10000 # sm4算法有硬件加速，取消硬件加速

```

# 添加侧信道防护测试
##  打补丁
```bash
# 将补丁文件放置在openssl_1_1_1wa-src同级目录下，进入 openssl_1_1_1wa-src 目录执行该命令
git apply ../0001-Add-defence-code-of-sm2-and-sm4.patch 
```
使用如下命令查看补丁是否应用成功
```bash
git status
```
成功应用补丁后时，会看到如下的变化
```text
modified:   crypto/sm2/sm2_crypt.c
modified:   crypto/sm2/sm2_sign.c
modified:   crypto/sm4/sm4.c
```

重复 **添加侧信道防护测试** 中的第3-7步。

## 附：添加打印信息调试
如需添加打印信息调试，可在openssl相应源代码中 `#include <stdio.h>` 使用 `fprintf` 输出相关打印信息，然后重新编译openssl库和测试程序。