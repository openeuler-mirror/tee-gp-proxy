# 鲲鹏920L/S/M模组烧录设备密钥和设备证书
本文档描述鲲鹏920L/S/M模组使用开源OPTEE OS在openEuler 22.03环境测试，完成装备环境烧录设备密钥和设备证书流程。使用本文档需提前安装装备BIOS，并获取已发布的和本文档配套使用的CA/TA；具体烧录具体如下：
## 1. 部署环境
### 1.1 编译安装开源optee_os
```
# 克隆
git clone https://github.com/OP-TEE/optee_os.git -b 4.9.0
cp 0001-open-source-community-optee-supports-920L.patch optee_os
cd optee_os
git apply --reject 0001-open-source-community-optee-supports-920L.patch

# 安装依赖
pip install cryptography

# 编译
make -j64 -C optee_os PLATFORM=d06 supported-ta-targets=ta_arm64

# 安装optee_os
cd optee_os/out/arm-plat-d06/core
# 安装tee.bin固件至flash空间0x1860000处，按实际大小烧写
```
重启机器，BIOS日志打印`TEE OS Load OK`，证明成功加载OPTEE OS
### 1.2 编译optee_client的teec库和守护进程
```
# 克隆
git clone https://github.com/OP-TEE/optee_client.git -b 4.9.0

# 编译teec库
make -C optee_client/libteec
cp optee_client/out/libteec/libteec.* /usr/lib64/

# 编译守护进程
make -C optee_client/tee-supplicant
cd optee_client/out/tee-supplicant
./tee-supplicant &
```
### 1.3 编译optee固件
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
insmod optee.ko
```

## 2.部署、运行CA/TA，生成密钥、证书
### 2.1 安装依赖
```
yum install openssl-devel
```
### 2.2 加载驱动
```
modprobe mtd
modprobe tee
insmod optee.ko 
```
### 2.3 部署CA/TA
```
mkdir /vendor/bin
cp op-dft-ca /vendor/bin
chmod +x /vendor/bin/op-dft-ca
mkdir /usr/lib/optee_armtz/
cp 21be2d5a-eef8-4940-ad16-95832f89290e.ta /usr/lib/optee_armtz/
```
### 2.4 生成密钥和证书
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
注：2.4章节命令2不可单独重复执行；如有需求，需将命令1都重新执行，生成并放置设备证书后，再执行命令2.
## 3.烧录密钥和设备证书
密钥和设备证书均以双备份形式烧录至flash上。完成密钥和设备证书的烧写，可正常启动商用Itrustee OS.具体烧写地址如下表，

|address|content|
| --- | --- |
|0x1810000|key.bin|
|0x1820000|key.bin|
|0x1830000|cert.bin|
|0x1840000|cert.bin|
|0x1860000|tee.bin/商用Itrustee|
