#!/bin/bash
set -xe

INSTALL_LOCATION=$1
NPROCESSORS=$2

BUILD_FLAGS="no-ssl3 no-ssl3-method no-zlib no-shared no-module no-comp no-dynamic-engine no-apps no-docs no-sm2-precomp no-atexit enable-ec_nistp_64_gcc_128"

tar zxf openssl.tar.gz
pushd openssl-*
./config ${BUILD_FLAGS} --prefix=${INSTALL_LOCATION}
make depend
make -j${NPROCESSORS}
make install_sw
popd
