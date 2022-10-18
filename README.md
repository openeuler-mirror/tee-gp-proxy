# cc-resource-pooling

#### 介绍
项目（TEE GP Proxy）旨在通过资源池化TrustZone的算力，方便客户在云景中在鲲鹏机密计算的节点部署可信应用。
详细内容可参考仓库中的设计文档。

#### 软件架构
![TrustZone资源池架构](docs/pic/arch-II.png)

本项目借助了gRPC这一字节流框架，扩展新创建了可部署在任意位置的GP(Globle Platform) API 库-下文称为GP Client，用于部署在云上的TrustZone的Client APP访问真实的TrustZone TEE。同时在Host上 新建了 GP API proxy，用于接收来自远程的CA的 GP API的调用。

GP Client用于序列化CA的GP接口调用，GP Proxy则收到调用合反序列化后，将GP调用转化为本地TEE Client接口调用。考虑到并发处理的情况，GP API Proxy可管理多任时的队列。
使用此方法，解决在VM或Docker中穿透虚拟化层访问TEE驱动的问题。如果需要，你也可以进一步开发，将多泰山服务器集群化管理。



#### 安装教程

参考部署文档。

#### 使用说明

1.  本项目原项目中引入了Host端对客户端的认证机制，并在GP API 以及Service侧提供了透传JWT的API，JWT的获取以及确认需要应用实现；
2.  在配置gPRC时，建议启用TLS以及基于证书的双向认证，注意证书私钥为机密数据，在部署系统时需要考虑保护机制；
3.  本项目不包含其它开源项目的代码，涉及的第三方开源组件均需要使用者自行获取。


#### 参与贡献


#### 特技
1. 项目提供接口与原接口完全适配，用户仅需更换libteec.so文件即可直接使用
2. 增加了token验证机制，并添加了两个扩展程序，作为token验证的中间件
3. 性能上相较于一期项目显著提升
