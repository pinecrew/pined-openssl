#!/bin/bash
set -xe

OPENSSL_VERSION=openssl-3.5.5
OPENSSL_SHA256=b28c91532a8b65a1f983b4c28b7488174e4a01008e29ce8e69bd789f28bc2a89
OPENSSL_URL="https://github.com/openssl/openssl/releases/download"

curl -Lo openssl.tar.gz "${OPENSSL_URL}/${OPENSSL_VERSION}/${OPENSSL_VERSION}.tar.gz"
echo "${OPENSSL_SHA256}  openssl.tar.gz" | sha256sum -c -
