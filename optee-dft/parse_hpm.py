#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.

import os
import sys
import tarfile
import logging


LEN_BIT = 8
BUF_OFFSET = [16, 32, 48]
TAR_GZ_OFFSET = 0x92E
TEE_OS_OFFSET = 0x1860000
TEE_OS_LEN = 0x7A0000
FLASH_TAR_GZ = "flash.tar.gz"
TEE_OS_BIN_FILE = "teeos.bin"


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[logging.StreamHandler()]
)


def get_tar_gz(data_buffer):
    offset = TAR_GZ_OFFSET
    for v in BUF_OFFSET:
        offset += int(data_buffer[v:v + LEN_BIT].decode('ascii'), 16)

    flash_tar_gz = data_buffer[offset:-1]
    with open(FLASH_TAR_GZ, 'wb') as f:
        f.write(flash_tar_gz)
        logging.info("parse flash.tar.gz success")


def decompress_flash():
    with tarfile.open(FLASH_TAR_GZ, 'r:gz') as tar:
        for member in tar.getmembers():
            if member.name == TEE_OS_BIN_FILE:
                tar.extract(member, path='.')
                break
        else:
            logging.error("teeos.bin not found in flash.tar.gz, parse failed")
            exit(1)
        os.remove(FLASH_TAR_GZ)
    logging.info("parse flash.bin success")


def parse_tee_bin():
    with open(TEE_OS_BIN_FILE, 'rb') as f:
        f.seek(TEE_OS_OFFSET)
        data = f.read(TEE_OS_LEN)
    with open(TEE_OS_BIN_FILE, 'wb') as out_f:
        out_f.write(data)
    logging.info("generate teeos.bin success")


def main():
    if len(sys.argv) != 2:
        logging.info("Usage: python3 parse_hpm.py *.hpm")
        exit(1)
    hpm_file = sys.argv[1]
    with open(hpm_file, 'rb') as f:
        data_buffer = f.read()

    get_tar_gz(data_buffer)
    decompress_flash()
    parse_tee_bin()


if __name__ == "__main__":
    main()
