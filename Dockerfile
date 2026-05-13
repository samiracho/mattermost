# syntax=docker/dockerfile:1.7
#
# Multi-arch Mattermost image for the samiracho/mattermost fork.
#
# Layout:
#   - mm-fetcher: downloads the upstream Team Edition tarball for $TARGETARCH;
#     supplies webapp client/, prepackaged_plugins/, i18n/, fonts/, templates/.
#   - go-builder: cross-compiles the forked Go server natively on $BUILDPLATFORM
#     so arm64 builds on an amd64 runner do not pay QEMU cost on the slow stage.
#   - runtime: minimal Debian image; replaces upstream bin/mattermost with the
#     freshly built fork binary.

ARG MM_VERSION=11.7.0
ARG DEBIAN_VERSION=12
ARG GO_VERSION=1.25.9

#############################################
# Stage 1 — fetch & unpack upstream Mattermost TE
#############################################
FROM --platform=$TARGETPLATFORM debian:${DEBIAN_VERSION}-slim AS mm-fetcher

ARG MM_VERSION
ARG TARGETARCH

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp
RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) MM_ARCH=amd64 ;; \
        arm64) MM_ARCH=arm64 ;; \
        *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://releases.mattermost.com/${MM_VERSION}/mattermost-team-${MM_VERSION}-linux-${MM_ARCH}.tar.gz" \
        | tar -xz

#############################################
# Stage 2 — build the forked Go server binary
#############################################
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-bookworm AS go-builder

ARG TARGETARCH

WORKDIR /src
COPY server/ ./server/

WORKDIR /src/server
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -tags sourceavailable -trimpath -ldflags='-s -w' \
        -o /out/mattermost ./cmd/mattermost

#############################################
# Stage 3 — runtime image
#############################################
FROM --platform=$TARGETPLATFORM debian:${DEBIAN_VERSION}-slim

ARG MM_VERSION
ENV MM_VERSION=${MM_VERSION}
ENV PATH="/mattermost/bin:${PATH}"

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        libc6 \
        libc-bin \
        tini \
        tzdata \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 2000 mattermost \
 && useradd -u 2000 -g 2000 -d /mattermost -s /usr/sbin/nologin mattermost

COPY --from=mm-fetcher --chown=mattermost:mattermost /tmp/mattermost /mattermost
COPY --from=go-builder --chown=mattermost:mattermost /out/mattermost /mattermost/bin/mattermost

RUN mkdir -p \
        /mattermost/data \
        /mattermost/logs \
        /mattermost/config \
        /mattermost/plugins \
        /mattermost/client/plugins \
 && chown -R mattermost:mattermost /mattermost

USER mattermost
WORKDIR /mattermost

EXPOSE 8065 8067

HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
    CMD curl -fs http://localhost:8065/api/v4/system/ping || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["mattermost"]
