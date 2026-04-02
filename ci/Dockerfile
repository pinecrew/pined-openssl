ARG PYPA_IMAGE

FROM quay.io/pypa/${PYPA_IMAGE} as builder
ARG NPROCESSORS=1
WORKDIR /root
RUN if stat /etc/redhat-release 1>&2 2>/dev/null; then \
        yum -y install binutils perl perl-IPC-Cmd perl-Time-Piece;\
    fi
ADD download-openssl.sh /root/download-openssl.sh
ADD install-openssl.sh /root/install-openssl.sh
RUN ./download-openssl.sh && ./install-openssl.sh /opt/openssl ${NPROCESSORS}

FROM quay.io/pypa/${PYPA_IMAGE}
COPY --from=builder /opt/openssl /opt/openssl
