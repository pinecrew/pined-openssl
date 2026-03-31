ARG PYPA_IMAGE
ARG OPENSSL_VERSION
ARG OPENSSL_SHA256
ARG BUILD_FLAGS

FROM quay.io/pypa/${PYPA_IMAGE} as builder
WORKDIR /root
RUN yum -y install binutils perl perl-IPC-Cmd perl-Time-Piece
ADD install_openssl.sh /root/install_openssl.sh
RUN ./install_openssl.sh /opt/openssl

FROM quay.io/pypa/${PYPA_IMAGE}
COPY --from=builder /opt/openssl /opt/openssl
