BINARY     := bridge-signer
BUILD_DIR  := ./bin
PROTO_DIR  := ./api/proto
GEN_DIR    := ./api/gen
PROTO_FILE := $(PROTO_DIR)/signer/v1/signer.proto

GOFLAGS    := -trimpath

.PHONY: all build clean proto

all: build

build:
	@echo ">> building $(BINARY)..."
	@mkdir -p $(BUILD_DIR)
	go build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY) ./cmd/bridge-signer


proto:
	@echo ">> generating proto..."
	@mkdir -p $(GEN_DIR)/signer/v1
	protoc \
		--proto_path=$(PROTO_DIR) \
		--go_out=$(GEN_DIR) \
		--go_opt=paths=source_relative \
		--go-grpc_out=$(GEN_DIR) \
		--go-grpc_opt=paths=source_relative \
		$(PROTO_FILE)
	@echo ">> proto generation complete"


proto-tools:
	@echo ">> installing proto tools..."
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	@echo ">> make sure $$GOPATH/bin is in your PATH"


tidy:
	go mod tidy

clean:
	@echo ">> cleaning..."
	rm -rf $(BUILD_DIR)