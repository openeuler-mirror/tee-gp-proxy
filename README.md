# tee-gp-proxy

## 介绍
项目（tee-gp-proxy）旨在通过各种手段，使得REE侧的CA可以在各种场景中使用TrustZone，包括RPC调用方式，以及在虚拟化场景下对TrustZone的访问。


## 方案介绍
### 机密计算资源池

通过在Host上部署基于Socket的Proxy，支持多个远程的客户端访问TEE。远程客户端可以是VM或容器，CA可以像在本地一样使用TEE。这种场景适合集成化部署TEE机密计算的节点，各种类型的客户端共享TEE资源池的方式。[方案详情](https://gitee.com/openeuler/tee-gp-proxy/blob/master/cc-resource-pooling/README.md)

### TrustZone感知的机密VM

这是一种可以让Guest OS可以感知Host硬件的TEE的方案，即VM中可以像在Host上一样来使用TrustZone的能力。该方案关注的是使用TEE能力的高效性，因此与TEE的通讯都是通过内存映射、拷贝的方式进行。同时驱动层也会对VM以及VM部署的应用进行维护和管理，确保只有在VM才可以获得其对应的应用的输出。







