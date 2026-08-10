# syntax=docker/dockerfile:1.7

FROM alpine:3.23

ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
ARG VERSION=dev
LABEL org.opencontainers.image.title="mitmania" \
      org.opencontainers.image.description="Distributed policy and interception proxy for controlled egress" \
      org.opencontainers.image.version=$VERSION

RUN apk add --no-cache ca-certificates \
    && mkdir -p /var/lib/mitmania /run/mitmania \
    && chown -R 65532:65532 /var/lib/mitmania /run/mitmania

COPY --chmod=0755 docker-binaries/${TARGETOS}-${TARGETARCH}${TARGETVARIANT}/mitmania /usr/bin/mitmania

ENV HOME=/var/lib/mitmania \
    XDG_CACHE_HOME=/var/lib/mitmania \
    XDG_RUNTIME_DIR=/run/mitmania

USER 65532:65532
VOLUME ["/var/lib/mitmania"]
EXPOSE 3128 443

CMD ["/usr/bin/mitmania"]
