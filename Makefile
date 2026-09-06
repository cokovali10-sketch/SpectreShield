# SpectreShield Makefile
BINARY=spectreshield
BUILD_DIR=build
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS=-ldflags "-X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME) -X main.gitCommit=$(GIT_COMMIT)"

.PHONY: all build clean test lint ebpf install help

all: build

help:
	@echo "SpectreShield - eBPF-powered EDR"
	@echo ""
	@echo "Targets:"
	@echo "  build      - Build the binary"
	@echo "  ebpf       - Build eBPF C programs"
	@echo "  all        - Build everything"
	@echo "  test       - Run tests"
	@echo "  lint       - Run linter"
	@echo "  clean      - Clean build artifacts"
	@echo "  install    - Install binary"
	@echo "  docker     - Build Docker image"
	@echo "  release    - Build release binaries"

build:
	@echo "Building $(BINARY)..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) ./cmd/spectreshield
	@echo "Built: $(BUILD_DIR)/$(BINARY)"

build-arm:
	@echo "Building $(BINARY) (arm64)..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-arm64 ./cmd/spectreshield

ebpf:
	@echo "Building eBPF programs..."
	clang -O2 -target bpf -c kernel/process_monitor.c -o kernel/process_monitor.o
	clang -O2 -target bpf -c kernel/network_monitor.c -o kernel/network_monitor.o
	clang -O2 -target bpf -c kernel/file_monitor.c -o kernel/file_monitor.o
	@echo "eBPF programs built"

test:
	@echo "Running tests..."
	go test -v -race ./...

test-cover:
	@echo "Running tests with coverage..."
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

lint:
	@echo "Running linter..."
	golangci-lint run ./...

clean:
	@echo "Cleaning..."
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html
	rm -f kernel/*.o
	rm -f spectreshield

install: build
	@echo "Installing $(BINARY)..."
	install -m 755 $(BUILD_DIR)/$(BINARY) /usr/local/bin/$(BINARY)

docker:
	@echo "Building Docker image..."
	docker build -t spectreshield:$(VERSION) .
	docker tag spectreshield:$(VERSION) spectreshield:latest

release: build build-arm
	@echo "Creating release..."
	@mkdir -p $(BUILD_DIR)/release
	cp $(BUILD_DIR)/$(BINARY) $(BUILD_DIR)/release/spectreshield-linux-amd64
	cp $(BUILD_DIR)/$(BINARY)-arm64 $(BUILD_DIR)/release/spectreshield-linux-arm64
	@echo "Release binaries in $(BUILD_DIR)/release/"

deb:
	@echo "Building Debian package..."
	@mkdir -p $(BUILD_DIR)/deb/usr/local/bin
	@mkdir -p $(BUILD_DIR)/deb/etc/systemd/system
	@mkdir -p $(BUILD_DIR)/deb/DEBIAN
	cp $(BUILD_DIR)/$(BINARY) $(BUILD_DIR)/deb/usr/local/bin/
	@echo "Package: spectreshield" > $(BUILD_DIR)/deb/DEBIAN/control
	@echo "Version: $(VERSION)" >> $(BUILD_DIR)/deb/DEBIAN/control
	@echo "Architecture: amd64" >> $(BUILD_DIR)/deb/DEBIAN/control
	@echo "Maintainer: SpectreShield Team" >> $(BUILD_DIR)/deb/DEBIAN/control
	@echo "Description: eBPF-powered EDR and Behavioral Threat Intelligence" >> $(BUILD_DIR)/deb/DEBIAN/control
	dpkg-deb --build $(BUILD_DIR)/deb $(BUILD_DIR)/spectreshield-$(VERSION).deb
