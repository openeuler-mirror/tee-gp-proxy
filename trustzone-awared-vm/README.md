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

### 配置文件

`vtz_proxy.conf`为 `vtz_proxy` 的配置文件，可在其中定义了最大虚机数量等参数，详细信息如下：

- `max_vm_count`：支持的最大虚机数量

- `numa_bindings`：`vtz_proxy` 线程池绑核配置

- `use_vcpuset`: 虚机TA绑核配置

### 端口

Host的vsock服务端占用Host 30000端口，保证可以与VM侧通信，部署环境请保证Host 30000端口未被使用。

## Host 环境搭建
> 注：如环境按历史版本说明部署过环境，需先删除如下目录及文件。
> rm -rf /lib/modules/$(uname -r)/kernel/drivers/trustzone
1. 安装依赖
    ```shell
    yum install gcc patch make kernel-devel-$(uname -r) ninja-build rpm-build
    yum install glib2 glib2-devel pixman-devel
    yum install openssl-devel
    yum install libxml2-devel libvirt-devel
    yum install compat-openssl11-libs # 当内核版本大于等于6.6需安装
    ```
2. `vhost_vsock`编译
    > 注：当系统内核使用4.19内核基线版本大于4.19.149时，vsock驱动代码需要根据基线做修改适配。具体可根据版本号参考https://elixir.bootlin.com/linux/v4.19.150/source/drivers/vhost/vsock对vsock对应版本驱动源码进行修改。
    > 示例修改：在vhost_vsock_handle_tx_kick函数前声明如下vhost_transport结构，同时修改virtio_transport_recv_pkt接口传参，增加&vhost_transport参数。
    ```
    static struct virtio_transport vhost_transport;

    virtio_transport_recv_pkt(pkt);改为virtio_transport_recv_pkt(&vhost_transport, pkt);
    ```
    1. 下载代码仓，进入Host路径，执行`build_vsock.sh`脚本，编译并替换系统vhost_vsock.ko驱动。
    ```shell
    git clone https://gitcode.com/openeuler/tee-gp-proxy.git
    cd tee-gp-proxy/trustzone-awared-vm/Host/
    sh build_vsock.sh
    ```
3. `tzdriver`和`client`编译安装
    1. 进入`itrustee_tzdriver`的根目录，补丁文件路径按照实际路径修改。
    ``` 
    git am ../tee-gp-proxy/trustzone-awared-vm/Host/tzdriver-00*.patch
    cd rpm
    sh build_rpm.sh
    rpm -ivh output/tzdriver-*.rpm
    ```
    > 如果是麒麟系统，需要在Makefile中 删除 `-fstack-protector-strong`
    >
    > 若kernel路径不正确，请自行修改Makefile中的KERN_DIR
    2. 进入`itrustee_client`的根目录，补丁文件路径按照实际路径修改，编译守护进程并安装。
    ```shell 
    git am ../tee-gp-proxy/trustzone-awared-vm/Host/client-00*.patch
    cd rpm
    sh build_rpm.sh
    rpm -ivh output/tee_client-*.rpm
    ```
4. `vtz_proxy`编译安装
    ```
    cd tee-gp-proxy/trustzone-awared-vm/Host/rpm/
    sh build_rpm.sh
    rpm -ivh output/vtz_proxy-*
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
    yum install make kernel-devel-$(uname -r) git gcc openssl-devel rpm-build
    yum install compat-openssl11-libs  # 当内核版本大于等于6.6需安装
    ```
2. 下载`tee-gp-proxy`仓库，其中包含`vtzdriver`与`virtio`(5.10内核)源码。
    ```
    git clone https://gitcode.com/openeuler/tee-gp-proxy.git
    ```
3. 编译`vtzdriver`并加载`vtzdriver.ko`
    ```shell
    cd tee-gp-proxy/trustzone-awared-vm/VM/rpm
    sh build_rpm.sh
    rpm -ivh vtzdriver-*
    ```
    > 如果是麒麟系统，需要在Makefile中 删除 `-fstack-protector-strong`
    >
    > 若kernel路径不正确，请自行修改Makefile中的KERN_DIR
4. `itrustee_client`编译安装
   1. 进入`itrustee_client`的根目录，补丁文件路径按照实际路径修改并编译。
        ```shell 
        git am ../tee-gp-proxy/trustzone-awared-vm/Host/client-00*.patch
        cd rpm
        sh build_rpm.sh
        rpm -ivh output/tee_client-*.rpm
        ```
## 开始运行
1. 确认`Host`环境已安装tzdriver, tee_client, vtz_proxy rpm包，`VM`环境安装好vtzdriver, tee_client rpm包，即可使用TEE环境运行CA。

## 故障恢复
1. `vtz_proxy` 优雅退出：
    1. 需要再次拉起`vtz_proxy`，然后在所有`VM`内手动终止正在执行的`CA`进程，并进行如下操作：
    ```
    systemctl stop teecd
    rmmod vtzdriver
    systemctl start teecd
    ```
    2. 最后再重新拉起CA进程。
2. `vtz_proxy` 强制退出：
	1. 需要再次拉起systemctl start vtz_proxy 进程，重启所有`VM`，并重新初始化环境。

## 更新相同主线内核版本下不同补丁版本内核
1. 当更新相同主线版本下不同补丁版本内核后，需做如下操作：
   1. 需重新执行2.1节脚本`sh build_vsock.sh`更新vhost_vsock.ko驱动。
   2. 如OS为麒麟系统，还需手动对Host的tzdriver、VM的vtzdriver驱动进行软链接到新内核下。
   > 示例：6.6.0-32.7.v2505.ky11内核版本，6.6.0是内核主线版本，32.7是内核的补丁版本。
   ```
   # Host DRIVER=tzdriver.ko
   # VM DRIVER=vtzdriver.ko
   ln -s /lib/modules/${OLD_KERNEL}/extra/$DRIVER \
         /lib/modules/${NEW_KERNEL}/extra/$DRIVER
   depmod -a
   ```

