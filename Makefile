BUILD_DIR ?= ./build

APP_NAME := spire-identity-exchange
CGO_ENABLED ?= 0

all: build test

build: deps
	@echo "--------------------------------"
	@echo "Building spire-identity-exchange..."
	@mkdir -p $(BUILD_DIR)/bin
	@CGO_ENABLED=$(CGO_ENABLED) go build -v -o $(BUILD_DIR)/bin/$(APP_NAME) ./cmd/spire-identity-exchange-server && \
	ls -l $(BUILD_DIR)/bin/$(APP_NAME) && \
	echo "$(APP_NAME) built successfully at $(BUILD_DIR)/bin/$(APP_NAME)"
	@echo "--------------------------------"

test: build
	@echo "Running tests for the $(APP_NAME)..."
	@go test -v ./... -coverprofile cover.out

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
	@rm -rf $(BUILD_DIR)/bin/$(APP_NAME) cover.out
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
