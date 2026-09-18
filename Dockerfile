FROM golang:1.25-alpine AS build

WORKDIR /src

# Dependencies first so source edits do not invalidate the module cache.
COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./
COPY src/ ./src/
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /mtls-proxy .

FROM alpine:3.22

RUN apk add --no-cache ca-certificates \
    && adduser -D -u 10001 -H -s /sbin/nologin proxy

COPY --from=build /mtls-proxy /usr/local/bin/mtls-proxy

# Unprivileged: the listener is above 1024, so no capabilities are needed.
USER 10001

EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/mtls-proxy", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/mtls-proxy"]
CMD ["proxy"]
