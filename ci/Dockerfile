ARG PYPA_IMAGE

FROM quay.io/pypa/${PYPA_IMAGE} as builder
ARG NPROCESSORS=1
ARG PREREQUISITES="echo 'No prerequisites'"
WORKDIR /root
RUN ${PREREQUISITES}
ADD download-openssl.sh /root/download-openssl.sh
ADD install-openssl.sh /root/install-openssl.sh
RUN ./download-openssl.sh && ./install-openssl.sh /opt/openssl ${NPROCESSORS}

FROM quay.io/pypa/${PYPA_IMAGE}
COPY --from=builder /opt/openssl /opt/openssl
