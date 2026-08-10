# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build

ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
ARG VERSION=dev

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 \
    GOOS=$TARGETOS \
    GOARCH=$TARGETARCH \
    GOARM=${TARGETVARIANT#v} \
    go build \
      -ldflags "-w -s -X main.version=$VERSION -buildid= -extldflags=static" \
      -buildvcs=false \
      -trimpath \
      -o /out/mitmania \
      ./cmd/mitmania

RUN mkdir -p /rootfs/var/lib/mitmania /rootfs/run/mitmania

FROM alpine:3.23

ARG VERSION=dev
LABEL org.opencontainers.image.title="mitmania" \
      org.opencontainers.image.description="Distributed policy and interception proxy for controlled egress" \
      org.opencontainers.image.version=$VERSION

RUN apk add --no-cache ca-certificates
COPY --from=build --chown=65532:65532 /rootfs/ /
COPY --from=build /out/mitmania /usr/bin/mitmania

ENV HOME=/var/lib/mitmania \
    XDG_CACHE_HOME=/var/lib/mitmania \
    XDG_RUNTIME_DIR=/run/mitmania

USER 65532:65532
VOLUME ["/var/lib/mitmania"]
EXPOSE 3128 443

CMD ["/usr/bin/mitmania"]
