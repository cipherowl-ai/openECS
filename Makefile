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

# Build targets
all: fmt clean build-debug build-release


# format
fmt:
	$(GOCMD) fmt ./address
	$(GOCMD) fmt cmd
	$(GOCMD) fmt ./reload
	$(GOCMD) fmt ./securedata
	$(GOCMD) fmt ./store


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

.PHONY: all build-debug build-release clean build-linux-debug build-linux-release prepare