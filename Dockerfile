# syntax=docker/dockerfile:1

# The OpenKCA container image: the static binary on scratch, nothing else
# but an empty /tmp, the data folder and the htmx license. It runs as
# 1000:1000 and keeps its configuration and databases in the volume
# /var/lib/openkca (config.yaml and the data folder data/); run
# "openkca setup" once to create the configuration there
# (docs/CONFIGURATION.md#container). It serves plain HTTP on 9080 and the
# CRLs on 9081 by default.
#
#   docker build --build-arg VERSION=$(cat VERSION) -t openkca .
#
# GO_VERSION follows the toolchain line of go.mod; the release workflow
# passes it from there.
ARG GO_VERSION=1.27.3

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION} AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY cmd ./cmd
COPY internal ./internal
# openkca setup and serve find the configuration in the volume without
# --config
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -buildvcs=false \
      -ldflags "-s -w -X main.version=$VERSION -X github.com/mailsvb/openkca/internal/config.packagedPath=/var/lib/openkca/config.yaml" \
      -o /out/openkca ./cmd/openkca
# SQLite needs a writable temporary folder; the data folder is the
# service user's alone
RUN mkdir -p /rootfs/tmp /rootfs/var/lib/openkca \
 && chmod 1777 /rootfs/tmp \
 && chmod 0700 /rootfs/var/lib/openkca \
 && chown 1000:1000 /rootfs/var/lib/openkca

FROM scratch
COPY --from=build /rootfs/ /
COPY --from=build --chmod=0755 /out/openkca /usr/bin/openkca
COPY --chmod=0644 internal/web/static/htmx.LICENSE /usr/share/licenses/openkca/htmx.LICENSE
USER 1000:1000
EXPOSE 9080 9081
VOLUME ["/var/lib/openkca"]
ENTRYPOINT ["/usr/bin/openkca"]
CMD ["serve"]
