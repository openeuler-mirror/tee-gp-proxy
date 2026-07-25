#!/bin/bash
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
# build rpms for vtz_proxy
set -eu

RPM_CURDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
RPMBUILD_PATH=${RPM_CURDIR}/rpmbuild
SPECS_DIR=${RPM_CURDIR}/SPECS
LIB_CODE_NAME=libboundscheck


#step1: enter vtz_proxy source code and compile
echo ${RPM_CURDIR}
cd ${RPM_CURDIR}/../vtzb_proxy
if [ ! -d "$LIB_CODE_NAME" ];then
    git clone https://gitcode.com/openeuler/libboundscheck.git
fi
make clean
make -j

#step2: build_rpm
mkdir -p ${RPMBUILD_PATH}/SOURCES
cp -a ${RPM_CURDIR}/../vtzb_proxy/vtz_proxy ${RPMBUILD_PATH}/SOURCES/
cp -a ${RPM_CURDIR}/SOURCES/vtz_proxy.service ${RPMBUILD_PATH}/SOURCES/
rpmbuild --define "_topdir ${RPMBUILD_PATH}" -bb ${SPECS_DIR}/vtz_proxy.spec

#step3: clean_dir
mkdir -p ${RPM_CURDIR}/output
cp -a ${RPM_CURDIR}/rpmbuild/RPMS/aarch64/* ${RPM_CURDIR}/output
[ -d "${RPM_CURDIR}/rpmbuild" ] && rm -rf ${RPM_CURDIR}/rpmbuild
cd ${RPM_CURDIR}/../vtzb_proxy
make clean