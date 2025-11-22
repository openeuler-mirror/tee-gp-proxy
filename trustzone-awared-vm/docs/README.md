## Host 环境搭建
1. 安装依赖
```shell
yum install gcc patch make  kernel-devel-$(uname -r) kernel-headers-$(uname -r) ninja-build
yum install glib2 glib2-devel pixman-devel
yum install openssl-devel
```
2. `vtzb_proxy`编译
    ```shell
    git clone https://gitee.com/openeuler/tee-gp-proxy.git
    git clone https://gitee.com/openeuler/libboundscheck.git
    cp -rf libboundscheck tee-gp-proxy/trustzone-awared-vm/Host/vtzb_proxy
    ```
	1. 按实际串口数量修改`tee-gp-proxy/trustzone-awared-vm/Host/vtzb_proxy/serial_port.h`，一个VM对应一个虚拟串口
    ```
    #define SERIAL_PORT_NUM			 15
    ```
    2. 编译
    ```shell
    cd tee-gp-proxy/trustzone-awared-vm/Host/vtzb_proxy
    make
    sudo cp ./vtz_proxy /usr/bin/vtz_proxy
    ```	
5. `tzdriver`和`client`编译安装
    1. 进入`itrustee_tzdriver`的父级目录，确保补丁文件和目标目录在同一级目录下， 补丁文件路径按照实际路径修改。
        1. ``` patch -p0 < tee-gp-proxy/trustzone-awared-vm/Host/itrustee_tzdriver.patch```
    1. 920 机型请参考[官方文档](https://www.hikunpeng.com/document/detail/zh/kunpengcctrustzone/trustzone/fg/kunpengtrustzone_20_0019.html)。
    2. 920 新型号请参考[官方文档](https://www.hikunpeng.com/document/detail/zh/kunpengcctrustzone/cca/devg/Kunpeng_ommercialcryptography_16_0015.html)
    3. 在`tzdriver`编译后，将`tzdriver.ko` 复制到指定目录
    ```bash 
    mkdir -p "/lib/modules/$(uname -r)/kernel/drivers/trustzone/"
    cp tzdriver.ko /lib/modules/$(uname -r)/kernel/drivers/trustzone
    ```

## qemu与虚机配置
1.	获取`qemu v6.2.0`源码
    ```
    git clone -b v6.2.0 https://git.qemu.org/git/qemu.git
    ```
4. Patch Application
    1. 进入目标目录 `qemu` 的父级目录，确保补丁文件和目标目录在同一级目录下，补丁文件路径按照实际路径修改。
    ```bash
    patch -p0 < tee-gp-proxy/trustzone-awared-vm/Host/qemu.patch
    patch -p0 < tee-gp-proxy/trustzone-awared-vm/Host/qemu-2.patch
    ```
5. 编译`qemu`
    ```bash
    cd qemu
    mkdir build
    cd build
    ../configure --target-list=aarch64-softmmu --disable-werror
    make -j
    ```
    > 注*：关于./configure这一步
    > 1.若出现GCC将warning视为error的报错，可通过 --disable-werror解决
    > 2.若提示gcc版本过低， 请升级gcc版本后再编译
6. 虚拟机镜像
    1. [openEuler22.03-LTS-SP4下载地址](https://repo.openeuler.org/openEuler-22.03-LTS-SP4/virtual_machine_img/aarch64/)
    2. [kylin-v10 qcow2镜像制作方法](./kylin-v10-qcow2/kylin-v10-qcow2.md)
7. 虚机配置请参考[虚机配置](./vm-libvirt.xml)
8.	定义并启动虚拟机
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
9. 多虚机配置
    ```xml
     <qemu:arg value='-chardev'/>
     <qemu:arg value='socket,path=/tmp/vm_vtzb_sock1,server=on,wait=off,id=vm01_vtzb_sock'/>
     <qemu:arg value='-device'/>
     <qemu:arg value='virtio-serial'/>
     <qemu:arg value='-device'/>
     <qemu:arg value='virtserialport,chardev=vm01_vtzb_sock,name=vtzf_serialport0'/>
    ```
    1. 在虚机配置文件中修改如上代码：`path`按照`/tmp/vm_vtzb_sock0`，`/tmp/vm_vtzb_sock1`，`/tmp/vm_vtzb_sock2`且接着上一个虚机配置文件中的`path`有序递增；
    2. 修改`id`与`chardev` 一致且唯一；
    3. `name` 恒为`vtzf_serialport0`；
## VM环境搭建
1. 安装依赖
```shell
yum install make kernel-devel-$(uname -r) kernel-headers-$(uname -r) git gcc openssl-devel 
```
1. `itrustee_client`编译安装
    1. 920 机型请参考[官方文档](https://www.hikunpeng.com/document/detail/zh/kunpengcctrustzone/trustzone/fg/kunpengtrustzone_20_0019.html)。
    2. 920 新型号请参考[官方文档](https://www.hikunpeng.com/document/detail/zh/kunpengcctrustzone/cca/devg/Kunpeng_ommercialcryptography_16_0015.html)
2. 下载`tee-gp-proxy`仓库，其中包含`vtzdriver`与`virtio`(5.10内核)源码。
    ```
    git clone https://gitee.com/openeuler/tee-gp-proxy.git
    git clone https://gitee.com/openeuler/libboundscheck.git
    cp -rf libboundscheck tee-gp-proxy/trustzone-awared-vm/VM/vtzdriver
    ```
3.	编译`virtio_console.ko`并加载（仅5.10内核需要执行此步骤）
	1. 编译`virtio_console` 并替换内核默认的`virtio_console`！
    ```
    cd tee-gp-proxy/trustzone-awared-vm/VM/virtio/char
    make
    cp virtio_console.ko /lib/modules/$(uname -r)/kernel/drivers/char
    cd /lib/modules/$(uname -r)/kernel/drivers/char
    mv virtio_console.ko.xz virtio_console.ko.xz.back
    xz -k -9 ./virtio_console.ko    
    rmmod virtio_console
    insmod /lib/modules/$(uname -r)/kernel/drivers/char/virtio_console.ko
    ```
8.	编译`vtzdriver`并加载`vtzfdriver.ko`, `vtzfdriver`加载后不可卸载, 如需卸载请重启
    ```bash
    cd tee-gp-proxy/trustzone-awared-vm/VM/vtzdriver
    make
    mkdir -p /lib/modules/$(uname -r)/kernel/drivers/trustzone
    cp vtzfdriver.ko /lib/modules/$(uname -r)/kernel/drivers/trustzone
    insmod /lib/modules/$(uname -r)/kernel/drivers/trustzone/vtzfdriver.ko
    ```
    > 如果是麒麟系统，需要在Makefile中 删除 `-fstack-protector-strong`
    > 若kernel路径不正确，请自行修改Makefile中的KERN_DIR

## RUN
首先要确认`Host`与`VM`中已搭建好`ccos`环境，然后执行以下命令：
#### 在`Host`中需要执行以下命令
```shell
insmod /lib/modules/$(uname -r)/kernel/drivers/trustzone/tzdriver.ko
nohup /usr/bin/teecd &
nohup /usr/bin/vtz_proxy &
```
#### 在`VM`中需要执行以下命令
```shell
rmmod virtio_console #仅5.10内核需要执行此步骤
insmod /lib/modules/$(uname -r)/kernel/drivers/char/virtio_console.ko #仅5.10内核需要执行此步骤
insmod /lib/modules/$(uname -r)/kernel/drivers/trustzone/vtzfdriver.ko
nohup /usr/bin/teecd &
```
