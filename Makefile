BUILD_DIR ?= ./build
CGO_ENABLED ?= 0

all: build test

# Format: APP_NAME:cmd/path:os/arch_list
# To add a new command, simply add a new line here.
APPS := \
	spire-credentialcomposer-identity-exchange:cmd/spire-credentialcomposer-identity-exchange:linux/amd64,linux/arm64 \
	spire-identity-exchange-server:cmd/spire-identity-exchange-server:linux/amd64,linux/arm64

# --- Build Logic ---

define build_app
	$(eval APP_NAME := $(word 1,$(subst :, ,$1)))
	$(eval APP_PATH := $(word 2,$(subst :, ,$1)))
	# Capture the full string of platforms
	$(eval PLATFORMS_STR := $(word 3,$(subst :, ,$1)))
	$(eval VAR_NAME := $(subst -,_,$(APP_NAME))_TAGS)
	$(eval CURRENT_TAGS := $($(VAR_NAME)))
	$(eval BUILD_TAG_FLAG := $(if $(CURRENT_TAGS),-tags $(CURRENT_TAGS),))

	# Replace commas with spaces so 'foreach' can iterate over them
	$(foreach platform,$(subst $(comma), ,$(PLATFORMS_STR)), \
		$(eval OS := $(word 1,$(subst /, ,$(platform)))) \
		$(eval ARCH := $(word 2,$(subst /, ,$(platform)))) \
		echo "Building $(APP_NAME) for $(OS)/$(ARCH) $(if $(CURRENT_TAGS),with tags: $(CURRENT_TAGS))..."; \
		mkdir -p $(BUILD_DIR)/$(OS)/$(ARCH); \
		GOOS=$(OS) GOARCH=$(ARCH) CGO_ENABLED=$(CGO_ENABLED) go build $(BUILD_TAG_FLAG) -o $(BUILD_DIR)/$(OS)/$(ARCH)/$(APP_NAME) ./$(APP_PATH); \
	)
endef

# Needed for the subst function to use a comma
comma := ,

build: deps
	@$(foreach app,$(APPS),$(call build_app,$(app)))

test:
	@$(foreach app,$(APPS), \
		$(eval APP_NAME := $(word 1,$(subst :, ,$(app)))) \
		$(eval VAR_NAME := $(subst -,_,$(APP_NAME))_TAGS) \
		$(eval CURRENT_TAGS := $($(VAR_NAME))) \
		$(eval BUILD_TAG_FLAG := $(if $(CURRENT_TAGS),-tags $(CURRENT_TAGS),)) \
		echo "Testing $(APP_NAME) $(if $(CURRENT_TAGS),with tags: $(CURRENT_TAGS))..."; \
		go test $(BUILD_TAG_FLAG) -v ./...; \
	)

deps:
	@echo "Downloading dependencies..."
	@go mod download
	@echo "Dependencies downloaded."

tidy:
	@echo "Tidying go.mod / go.sum..."
	@go mod tidy
	@echo "go.mod / go.sum tidied."

clean:
	@echo "Cleaning up..."
	@rm -rf $(BUILD_DIR)
	@echo "Cleanup completed."

proto:
	@echo "Generating protobuf code..."
	@$(MAKE) proto-gen
	@echo "Protobuf code generation completed."

proto-gen:
	@echo "Finding proto dependencies..."
	@GOMODCACHE=$$(go env GOMODCACHE) && \
	SPIRE_API_SDK_VERSION=$$(grep 'github.com/spiffe/spire-api-sdk' go.mod | grep -v '//' | awk '{print $$2}') && \
	SPIRE_PROTO_PATH="$$GOMODCACHE/github.com/spiffe/spire-api-sdk@$$SPIRE_API_SDK_VERSION/proto" && \
	GW_VERSION=$$(grep 'github.com/grpc-ecosystem/grpc-gateway/v2' go.mod | grep -v '//' | awk '{print $$2}') && \
	GOOGLEAPIS_PROTO_PATH="$$GOMODCACHE/github.com/grpc-ecosystem/grpc-gateway/v2@$$GW_VERSION/third_party/googleapis" && \
	if [ ! -d "$$SPIRE_PROTO_PATH" ]; then \
		echo "Downloading SPIRE API SDK..."; \
		go mod download github.com/spiffe/spire-api-sdk; \
	fi && \
	if [ ! -d "$$GOOGLEAPIS_PROTO_PATH" ]; then \
		echo "Downloading grpc-gateway..."; \
		go mod download github.com/grpc-ecosystem/grpc-gateway/v2; \
	fi && \
	echo "SPIRE proto path: $$SPIRE_PROTO_PATH" && \
	echo "googleapis proto path: $$GOOGLEAPIS_PROTO_PATH" && \
	cd api && \
	protoc \
		-I. \
		-I$$SPIRE_PROTO_PATH \
		-I$$GOOGLEAPIS_PROTO_PATH \
		--go_out=. \
		--go_opt=paths=source_relative \
		--go-grpc_out=. \
		--go-grpc_opt=paths=source_relative \
		--grpc-gateway_out=. \
		--grpc-gateway_opt=paths=source_relative \
		SpireIdentityExchangeApi.proto && \
	echo "Generated SpireIdentityExchangeApi.pb.go, SpireIdentityExchangeApi_grpc.pb.go and SpireIdentityExchangeApi.pb.gw.go"

.PHONY: all build test deps tidy proto proto-gen clean
