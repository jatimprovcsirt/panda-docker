# PANDA Docker — containerized field-level encryption.
#
# Three properties drive every choice here:
#
#   1. Nothing in the image is useful to an attacker who gets inside it.
#   2. The image is reproducible: the same commit and version produce the same
#      binary.
#   3. The container holds no key material and writes nothing, so it can be
#      discarded and replaced without ceremony.

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
FROM golang:1.26-bookworm AS build

WORKDIR /src

# Dependencies first, so a source-only change does not re-download the module
# graph. This is the difference between a 90-second and a 10-second rebuild on
# every commit.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=0.0.0
ARG COMMIT=unknown

# CGO_ENABLED=0 produces a static binary with no libc dependency, which is what
# lets the runtime stage be distroless. -trimpath removes the builder's
# filesystem paths from the binary, so a published artifact does not leak the
# directory layout of whoever built it.
RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags="-s -w \
        -X main.version=${VERSION} \
        -X main.commit=${COMMIT}" \
      -o /out/panda-docker ./cmd/panda-docker

# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------
#
# distroless/static: no shell, no package manager, no curl, no busybox. A
# compromised container has nothing to pivot with — no `wget` to fetch a
# second stage, no `sh` to run one. It also carries CA roots, which the Vault
# and Infisical key providers need for TLS.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/panda-docker /panda-docker

# 65532 is the distroless `nonroot` user. Stated explicitly rather than relying
# on the base image's default, so a future change to the base cannot silently
# make this run as root.
USER 65532:65532

# 8080/9090 are the API ports — exactly one is ever bound, chosen by
# PANDA_API_PROTOCOL. 8081 is the health and metrics listener, always on.
EXPOSE 8080 9090 8081

# No shell exists in this image, so the probe has to be the binary itself. The
# `healthcheck` subcommand is why it exists — without it there is no way to
# express a Docker healthcheck in a distroless container at all.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/panda-docker", "healthcheck", "--url=http://127.0.0.1:8081/readyz"]

ENTRYPOINT ["/panda-docker"]
