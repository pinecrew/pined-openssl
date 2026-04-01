#!/bin/bash
set -xe

INSTALL_LOCATION=$1

OPENSSL_URL="https://github.com/openssl/openssl/releases/download"

curl -Lo openssl.tar.gz "${OPENSSL_URL}/${OPENSSL_VERSION}/${OPENSSL_VERSION}.tar.gz"
echo "${OPENSSL_SHA256}  openssl.tar.gz" | shasum -a 256 -c
tar zxf openssl.tar.gz
pushd ${OPENSSL_VERSION}
./config ${BUILD_FLAGS} --prefix=${INSTALL_LOCATION} --openssldir=${INSTALL_LOCATION}
make depend
make -j4
# avoid installing the docs
# https://github.com/openssl/openssl/issues/6685#issuecomment-403838728
make install_sw install_ssldirs
popd
