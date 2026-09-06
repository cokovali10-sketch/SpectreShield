# SpectreShield Dockerfile
FROM golang:1.22-bookworm AS builder

RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-amd64 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN GOOS=linux GOARCH=amd64 go build -o /spectreshield ./cmd/spectreshield

# Runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    iptables \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /spectreshield /usr/local/bin/spectreshield

RUN useradd -r -s /bin/false spectreshield || true

EXPOSE 8080

ENTRYPOINT ["spectreshield"]
CMD ["start", "--foreground"]
