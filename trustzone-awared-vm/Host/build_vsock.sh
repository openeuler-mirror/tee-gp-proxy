#!/bin/bash
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
# build rpms for vtz_proxy
set -eu

CURDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
KERNEL_VERSION=$(uname -r)
KERNEL_MAJOR_VERSION=$(uname -r | awk -F. '{printf "%s.%s\n", $1, $2}')
VOSCK_BUILD_PATH="$CURDIR/vsock-$KERNEL_MAJOR_VERSION"
TARGET_VSOCK_PATH=/lib/modules/$KERNEL_VERSION/kernel/drivers/vhost/vhost_vsock.ko.xz

#step1: enter vtz_proxy source code and compile
cd $VOSCK_BUILD_PATH
make clean
make -j

#step2: replace all vhost_vsock.xz
xz -z -f vhost_vsock.ko
cp -a vhost_vsock.ko.xz $TARGET_VSOCK_PATH
for kernel_dir in /lib/modules/*/; do
    kernel_version=$(basename "$kernel_dir")
    [ "$kernel_version" = "$KERNEL_VERSION" ] && continue

    link_dir="${kernel_dir}kernel/drivers/vhost/"
    mkdir -p "$link_dir"
    ln -sf $TARGET_VSOCK_PATH "${link_dir}vhost_vsock.ko.xz"
done

/usr/sbin/depmod -a
make clean