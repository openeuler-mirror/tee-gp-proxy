# tee-gp-proxy

## Introduction

tee-gp-proxy aims to enable the CA on the REE to use the TrustZone across diverse scenarios, including RPC invoking mode and access to the TrustZone in virtualization scenarios.

## Solution Introduction

### Confidential Computing Resource Pool

A Socket-based proxy is deployed on a host to allow multiple remote clients to access the TEE. The remote client can be a VM or container, and the CA can use the TEE as if it were a local TEE. This scenario is applicable to the integrated deployment of TEE confidential computing nodes, and various types of clients share the TEE resource pool. For more information, see [solution details](https://gitee.com/openeuler/tee-gp-proxy/blob/master/cc-resource-pooling/README.md).

### TrustZone-Aware Confidential VM

This solution enables the guest OS to sense the TEE of the host hardware. That is, the VM can use the TrustZone capability as on the host. This solution focuses on high efficiency of using the TEE capability. Therefore, communication with the TEE is performed by using memory mapping and copy. Additionally, the driver layer also maintains and manages VMs and applications deployed on VMs, ensuring that application outputs are accessible exclusively within their designated VM.
