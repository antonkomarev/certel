FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Stamp the version so -version, the startup log and /healthz report a real
# build instead of "dev"; compute VERSION outside the build (git describe) and
# pass it as a build-arg — .git is not part of the build context.
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" -o /certel ./cmd/certel

FROM alpine:3.21
# ca-certificates: system trust store for verifying public chains.
RUN apk add --no-cache ca-certificates && adduser -D -H monitor \
    && mkdir -p /opt/certel/db && chown monitor /opt/certel/db
USER monitor
COPY --from=build /certel /opt/certel/certel
# Default database location is the db/ directory next to the binary; mount a
# volume there so alert state survives container recreation.
VOLUME /opt/certel/db
EXPOSE 8880
# Self-contained liveness check (no curl/wget in the image): the binary hits
# its own /healthz, which reflects scheduler progress, not just HTTP liveness.
HEALTHCHECK --interval=60s --timeout=5s --start-period=30s \
    CMD ["/opt/certel/certel", "healthcheck", "-config", "/etc/certel/config.yaml"]
ENTRYPOINT ["/opt/certel/certel"]
CMD ["monitor", "-config", "/etc/certel/config.yaml"]
