# trustzone-awared-vm

## 介绍

项目（trustzone-awared-vm）旨在通过各种手段，使得REE侧的CA可以在虚拟化场景下使用TrustZone。 

## 软件架构

本项目借助内核 vhost_vsock驱动的接发消息能力，构建TrustZone感知的机密虚拟机。构建vtzdriver，提供与tzdriver相同的接口供上层应用和库调用。在Host侧创建vsock服务端，在VM侧创建vsock客户端，连通VM与Host。vtz_proxy接受识别由vtzdriver转发的tzdriver调用，识别后调用tzdriver对应接口。调用结果由vtz_proxy、vsock、vtzdriver返回给上层应用。从而实现在VM中使用TEE的体验与本地Host上无差异。

## 使用说明

1. 本项目不包含其它开源项目的代码，涉及的第三方开源组件均需要使用者自行获取。

## 参与贡献

## 特技

1. 项目提供接口与原接口完全适配，用户无需修改应用
2. 支持虚拟机使用switchless特性

---
---
# 环境搭建
本项目为鲲鹏多种型号服务器提供了host和vm环境部署脚本，详见`utils/ccos-env-deploy`。以下为手动部署的详细操作说明。

## 前置要求

手动部署之前，请确保满足以下条件：

### 必需文件准备

将 `vtzb_proxy.conf` 放置在 `/var/vtzb/` 目录下

### 配置文件

`vtzb_proxy.conf`为 `vtz_proxy` 的配置文件，可在其中定义了最大虚机数量等参数，详细信息如下：

- `max_vm_count`：支持的最大虚机数量

- `numa_bindings`：`vtz_proxy` 线程池绑核配置

### 端口

Host的vsock服务端占用Host 30000端口，保证可以与VM侧通信，部署环境请保证Host 30000端口未被使用。

## Host 环境搭建

1. 安装依赖
    ```shell
    yum install gcc patch make  kernel-devel-$(uname -r) ninja-build
    yum install glib2 glib2-devel pixman-devel
    yum install openssl-devel
    yum install libxml2-devel libvirt-devel
    yum install compat-openssl11-libs # 当内核版本大于等于6.6需安装
    ```
2. `vtzb_proxy`编译
    ```shell
    git clone https://gitcode.com/openeuler/tee-gp-proxy.git
    git clone https://gitcode.com/openeuler/libboundscheck.git
    cp -rf libboundscheck tee-gp-proxy/trustzone-awared-vm/Host/vtzb_proxy
    ```
   
    1. 编译
        ```shell
        cd tee-gp-proxy/trustzone-awared-vm/Host/vtzb_proxy
        make
        sudo cp ./vtz_proxy /usr/bin/vtz_proxy
        ```	
3. `vhost_vsock`编译
    1. 根据实际内核版本4.19、5.10、6.6，进入对应vsock源码目录，执行编译后，将`vhost_vsock.ko` 复制到指定目录。
    ```shell
    cd tee-gp-proxy/trustzone-awared-vm/Host/vsock-$(uname -r | awk -F. '{printf "%s.%s\n", $1, $2}')
    make
    mkdir -p "/lib/modules/$(uname -r)/kernel/drivers/trustzone/"
    cp vhost_vsock.ko /lib/modules/$(uname -r)/kernel/drivers/trustzone
    ```
4. `tzdriver`和`client`编译安装
    1. 进入`itrustee_tzdriver`的根目录，补丁文件路径按照实际路径修改。
    ``` 
    git am ../tee-gp-proxy/trustzone-awared-vm/Host/tzdriver-00*.patch
    ```
    2. 进入`itrustee_client`的根目录，补丁文件路径按照实际路径修改。
    ```shell 
    git am ../tee-gp-proxy/trustzone-awared-vm/Host/client-0001-add-vm-uid-in-TC_NS_ClientContext.patch
    ```
    3. 920 机型请参考[官方文档](https://www.hikunpeng.com/document/detail/zh/kunpengcctrustzone/trustzone/fg/kunpengtrustzone_20_0019.html)。
    4. 920 新型号请参考[官方文档](https://www.hikunpeng.com/document/detail/zh/kunpengcctrustzone/cca/devg/Kunpeng_ommercialcryptography_16_0015.html)
    5. 在`tzdriver`编译后，将`tzdriver.ko` 复制到指定目录
        ```shell 
        cp tzdriver.ko /lib/modules/$(uname -r)/kernel/drivers/trustzone
        ```
## qemu与虚机配置
1.	获取`qemu v6.2.0`源码
    ```shell
    git clone -b v6.2.0 https://git.qemu.org/git/qemu.git
    ```
2. 编译`qemu`
    ```shell
    cd qemu
    mkdir build
    cd build
    ../configure --target-list=aarch64-softmmu --disable-werror
    make -j
    ```
    > 注*：关于./configure这一步
    >
    > 1.若出现GCC将warning视为error的报错，可通过 --disable-werror解决
    >
    > 2.若提示gcc版本过低， 请升级gcc版本后再编译
3. 虚拟机镜像
    1. [openEuler22.03-LTS-SP4下载地址](https://repo.openeuler.org/openEuler-22.03-LTS-SP4/virtual_machine_img/aarch64/)
    2. [kylin-v10 qcow2镜像制作方法](docs/kylin-v10-qcow2/kylin-v10-qcow2.md)
4. 虚机配置请参考[虚机配置](docs/vm-libvirt.xml)
5. 定义并启动虚拟机
    1. 安装依赖：
        ```shell
        yum -y install edk2-aarch64.noarch libvirt
        ```
    2. 启动虚机
        ```shell
        systemctl start/restart libvirtd.service
        setenforce 0
        virsh define vm-libvirt.xml
        virsh start nvm-ta-1
        /* 若新安装，用VNC登录安装，注意打开端口防火墙 */
        iptables -I INPUT -p tcp –dport 5901 -j ACCEPT
        ```
## VM环境搭建
1. 安装依赖
    ```shell
    yum install make kernel-devel-$(uname -r) git gcc openssl-devel 
    yum install compat-openssl11-libs  # 当内核版本大于等于6.6需安装
    ```
2. 下载`tee-gp-proxy`仓库，其中包含`vtzdriver`与`virtio`(5.10内核)源码。
    ```
    git clone https://gitcode.com/openeuler/tee-gp-proxy.git
    git clone https://gitcode.com/openeuler/libboundscheck.git
    cp -rf libboundscheck tee-gp-proxy/trustzone-awared-vm/VM/vtzdriver
    ```
3. `itrustee_client`编译安装
    1. 进入`itrustee_client`的根目录，补丁文件路径按照实际路径修改。
        1. ``` git am ../tee-gp-proxy/trustzone-awared-vm/Host/client-00*.patch```
    2. 920 机型请参考[官方文档](https://www.hikunpeng.com/document/detail/zh/kunpengcctrustzone/trustzone/fg/kunpengtrustzone_20_0019.html)。
    3. 920 新型号请参考[官方文档](https://www.hikunpeng.com/document/detail/zh/kunpengcctrustzone/cca/devg/Kunpeng_ommercialcryptography_16_0015.html)
4. 编译`vtzdriver`并加载`vtzfdriver.ko`
    ```shell
    cd tee-gp-proxy/trustzone-awared-vm/VM/vtzdriver
    make
    mkdir -p /lib/modules/$(uname -r)/kernel/drivers/trustzone
    cp vtzfdriver.ko /lib/modules/$(uname -r)/kernel/drivers/trustzone
    insmod /lib/modules/$(uname -r)/kernel/drivers/trustzone/vtzfdriver.ko
    ```
    > 如果是麒麟系统，需要在Makefile中 删除 `-fstack-protector-strong`
    >
    > 若kernel路径不正确，请自行修改Makefile中的KERN_DIR

## 开始运行
首先要确认`Host`与`VM`中已搭建好`ccos`环境，然后每次重启后需执行以下命令：
#### 在`Host`中需要按顺序执行以下命令，请确保vsock相关命令先执行，且需在虚机启动前执行
```shell
modprobe vmw_vsock_virtio_transport_common && modprobe vhost
insmod /lib/modules/$(uname -r)/kernel/drivers/trustzone/vhost_vsock.ko
insmod /lib/modules/$(uname -r)/kernel/drivers/trustzone/tzdriver.ko
nohup /usr/bin/teecd &
nohup /usr/bin/vtz_proxy &
```
#### 在`VM`中需要执行以下命令

1. 加载`vtzfdriver.ko`和`teecd`
```bash
insmod /lib/modules/$(uname -r)/kernel/drivers/trustzone/vtzfdriver.ko
nohup /usr/bin/teecd &
```

## 故障恢复
1. `vtz_proxy` 优雅退出：
    1. 需要再次拉起`vtz_proxy`，然后在所有`VM`内手动终止正在执行的`CA`进程，并进行如下操作：
    ```
    kill -9 $(pgrep teecd)
    rmmod vtzfdriver.ko 
    insmod vtzdriver.ko
    nohup /usr/bin/teecd &
    ```
    2. 最后再重新拉起CA进程。
2. `vtz_proxy` 强制退出：
	1. 需要再次拉起`vtz_proxy` 进程，重启所有`VM`，并重新初始化环境。
