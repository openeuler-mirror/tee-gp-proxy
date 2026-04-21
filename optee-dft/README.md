# 鲲鹏920L/S/M模组烧录设备密钥和设备证书
本文档描述鲲鹏920L/S/M模组使用开源OPTEE OS在openEuler 22.03环境测试，完成装备环境烧录设备密钥和设备证书流程。使用本文档需获取工具版BIOS、商用版BIOS和已发布的和本文档配套使用的CA/TA。预先安装装备BIOS；具体烧录具体如下：
## 1. 部署环境
### 1.1 安装依赖
```
yum install kernel-devel-$(uname -r) openssl-devel
pip install cryptography pyelftools
```
### 1.2 编译安装开源optee_os
#### 1.2.1 获取安全内存地址
1. 安装装备BIOS启动OS后，可通过BMC下载并查看BIOS启动日志，手动获取安全内存起始地址，具体方式如下：
2. 网页访问BMC ip，输入BMC用户名和密码，进入BMC网页控制页面，在`维护诊断`->`系统日志`->`systemcom.tar`处下载串口日志，搜索类似`Base=*, Size=0x40000000`日志，获取到最新日志中的`Base`地址。
3. 注：同一机型，在内存配置不变的情况下，安全内存地址相同。

#### 1.2.2 安装OPTEE_OS
```
# 克隆
git clone https://github.com/OP-TEE/optee_os.git -b 4.9.0
cp 0001-open-source-community-optee-supports-920L.patch optee_os
cd optee_os

# 按1.2.1章节获取安全内存地址`Base`地址设置到如下命令。
sed -i 's/0x2140000000/安全内存地址/g' 0001-open-source-community-optee-supports-920L.patch

git apply --reject 0001-open-source-community-optee-supports-920L.patch

# 编译
make -j64 -C optee_os PLATFORM=d06 supported-ta-targets=ta_arm64

# 安装
# 将optee_os/out/arm-plat-d06/core/tee.bin固件烧录至flash的0x1860000地址处。
```
|address|content|
| --- | --- |
|0x1860000|tee.bin|

重启机器，BIOS日志打印`TEE OS Load OK`，证明成功加载OPTEE OS
### 1.3 编译optee_client的teec库和守护进程
```
# 克隆
git clone https://github.com/OP-TEE/optee_client.git -b 4.9.0

# 编译teec库
make -C optee_client/libteec
cp optee_client/out/libteec/libteec.* /usr/lib64/

# 编译守护进程
make -C optee_client/tee-supplicant
```
### 1.4 编译optee固件
```
# 克隆
git clone https://gitcode.com/openeuler/kernel.git -b OLK-5.10

# 配置编译文件
cd kernel/drivers/tee/optee
# 使用如下`Makefile`替换`kernel/drivers/tee/optee`目录下的`Makefile`
-----Makefile-----
ifeq ($(KERNELRELEASE),)
	KERNELDIR ?= /lib/modules/`uname -r`/build
	PWD := $(shell pwd) 
modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules  
clean:
	rm -rf *.o *.ko *.mod.c *.symvers *.order *.cmd *.swp *.unsigned  

else
	optee-objs := call.o core.o device.o rpc.o shm_pool.o supp.o
	obj-m := optee.o  
endif

# 编译加载
sed -i 's/CONFIG_OPTEE_SHM_NUM_PRIV_PAGES/1/g' core.c
make
```

## 2.部署、运行CA/TA，生成密钥、证书
### 2.1 加载驱动
```
modprobe mtd
modprobe tee
cd kernel/drivers/tee/optee
insmod optee.ko 
cd optee_client/out/tee-supplicant
./tee-supplicant &
```
### 2.2 部署CA/TA
```
mkdir -p /vendor/bin
cp op-dft-ca /vendor/bin
chmod +x /vendor/bin/op-dft-ca
mkdir -p /usr/lib/optee_armtz/
cp 21be2d5a-eef8-4940-ad16-95832f89290e.ta /usr/lib/optee_armtz/
```
### 2.3 生成密钥和证书
准备证书中心，将根证书（下面以ca.crt为根名称为例）放在CA同目录下，生成密钥烧录包和设备证书烧录包。
```
# 命令0
/vendor/bin/op-dft-ca 0
# 命令1
/vendor/bin/op-dft-ca 1 /vendor/bin/ca.crt
```
使用生成的设备证书请求文件`certreq.csr.pem`请求设备证书（下面以cert.crt为设备证书名称为例），放到CA同目录`/vendor/bin`下，继续生成设备证书烧录包。
```
# 命令2
/vendor/bin/op-dft-ca 2 /vendor/bin/ca.crt /vendor/bin/cert.crt
```
此时/vendor/bin/目录下已成功获取密钥烧录包（key.bin）和设备证书烧录包(cert.bin)。
注：2.4章节命令2不可单独重复执行；如有需求，需将命令1都重新执行，生成并放置设备证书后，再执行命令2。
## 3.烧录密钥和设备证书
密钥和设备证书均以双备份形式烧录至flash上。完成密钥和设备证书的烧写，可正常启动商用Itrustee OS.具体烧写地址如下表，

|address|content|
| --- | --- |
|0x1810000|key.bin|
|0x1820000|key.bin|
|0x1830000|cert.bin|
|0x1840000|cert.bin|
## 4. 替换商用CCOS
完成装备环节密钥和设备证书预置后，下载[商用CCOS安装包：BoostKit-VF_teeos_2.3.x.zip](https://www.hikunpeng.com/developer/download)，解压后进入文件夹，执行`pares_hpm.py`脚本获取`teeos.bin`文件，直接烧录到flash的0x1860000上。
```
# 输入待提取HPM包名称，生成teeos.bin
python3 pares_hpm.py *.hpm
```

|address|content|
| --- | --- |
|0x1860000|teeos.bin|

安装商用BIOS后，即可成功启动商用CCOS。