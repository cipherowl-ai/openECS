# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
BINARY_NAME=pa
BINARY_UNIX=$(BINARY_NAME)_unix
TARGET_DIR=target

# Build flags
DEBUG_FLAGS=-gcflags="all=-N -l"
RELEASE_FLAGS=-ldflags="-s -w" -trimpath

# Protobuf parameters
PROTOC=protoc
PROTO_DIR=proto

# Build targets
all: proto fmt clean build-debug build-release

# Generate protobuf code
proto:
	@echo "Generating Go code from protobuf definitions..."
	$(PROTOC) --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		$(PROTO_DIR)/ecsd.proto
	@echo "Proto generation complete"

# format
fmt:
	$(GOCMD) fmt ./address
	$(GOCMD) fmt ./cmd
	$(GOCMD) fmt ./reload
	$(GOCMD) fmt ./securedata
	$(GOCMD) fmt ./store
	$(GOCMD) fmt ./proto
	$(GOCMD) fmt ./ecsd


build-debug: prepare
	$(GOBUILD) $(DEBUG_FLAGS) -o $(TARGET_DIR)/debug/$(BINARY_NAME)-cli ./cmd/cli
	$(GOBUILD) $(DEBUG_FLAGS) -o $(TARGET_DIR)/debug/$(BINARY_NAME)-server ./cmd/server
	$(GOBUILD) $(DEBUG_FLAGS) -o $(TARGET_DIR)/debug/$(BINARY_NAME)-ecsd ./ecsd

build-release: prepare
	$(GOBUILD) $(RELEASE_FLAGS) -o $(TARGET_DIR)/release/$(BINARY_NAME)-cli ./cmd/cli
	$(GOBUILD) $(RELEASE_FLAGS) -o $(TARGET_DIR)/release/$(BINARY_NAME)-server ./cmd/server
	$(GOBUILD) $(RELEASE_FLAGS) -o $(TARGET_DIR)/release/$(BINARY_NAME)-ecsd ./ecsd
prepare:
	mkdir -p $(TARGET_DIR)/debug
	mkdir -p $(TARGET_DIR)/release

clean:
	$(GOCLEAN)
	rm -rf $(TARGET_DIR)

# Cross compilation
build-linux-debug: prepare
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) $(DEBUG_FLAGS) -o $(TARGET_DIR)/debug/$(BINARY_UNIX)-cli ./cmd/cli
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) $(DEBUG_FLAGS) -o $(TARGET_DIR)/debug/$(BINARY_UNIX)-server ./cmd/server
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) $(DEBUG_FLAGS) -o $(TARGET_DIR)/debug/$(BINARY_UNIX)-ecsd ./ecsd

build-linux-release: prepare
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) $(RELEASE_FLAGS) -o $(TARGET_DIR)/release/$(BINARY_UNIX)-cli ./cmd/cli
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) $(RELEASE_FLAGS) -o $(TARGET_DIR)/release/$(BINARY_UNIX)-server ./cmd/server
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) $(RELEASE_FLAGS) -o $(TARGET_DIR)/release/$(BINARY_UNIX)-ecsd ./ecsd

build-docker:
	# if ths is linux
	if [ "$(shell uname -s)" = "Linux" ]; then
		make
		docker build -t ecsd -f ecsd/Dockerfile .
	else
		echo "This build process is designed for Linux systems only."
	fi

.PHONY: all proto build-debug build-release clean build-linux-debug build-linux-release prepare
