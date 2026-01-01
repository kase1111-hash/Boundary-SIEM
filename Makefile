.PHONY: all build test run clean lint fmt deps

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GORUN=$(GOCMD) run
GOFMT=$(GOCMD) fmt
GOVET=$(GOCMD) vet
GOMOD=$(GOCMD) mod

# Binary names
BINARY_INGEST=siem-ingest

# Directories
CMD_DIR=./cmd
BIN_DIR=./bin
INTERNAL_DIR=./internal

# Build flags
BUILD_FLAGS=-ldflags="-s -w"

all: deps build

## deps: Download and tidy dependencies
deps:
	$(GOMOD) download
	$(GOMOD) tidy

## build: Build all binaries
build: build-ingest

## build-ingest: Build the ingest service
build-ingest:
	mkdir -p $(BIN_DIR)
	$(GOBUILD) $(BUILD_FLAGS) -o $(BIN_DIR)/$(BINARY_INGEST) $(CMD_DIR)/siem-ingest

## run: Run the ingest service
run:
	$(GORUN) $(CMD_DIR)/siem-ingest/main.go

## test: Run all tests
test:
	$(GOTEST) -v -race -cover ./...

## test-coverage: Run tests with coverage report
test-coverage:
	$(GOTEST) -v -race -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

## test-unit: Run unit tests only
test-unit:
	$(GOTEST) -v -short ./...

## lint: Run linters
lint:
	$(GOVET) ./...
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed, skipping"; \
	fi

## fmt: Format code
fmt:
	$(GOFMT) ./...

## clean: Clean build artifacts
clean:
	rm -rf $(BIN_DIR)
	rm -f coverage.out coverage.html

## docker-build: Build Docker image
docker-build:
	docker build -t boundary-siem/ingest:latest -f Dockerfile.ingest .

## help: Show this help
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^## ' Makefile | sed 's/## /  /'
