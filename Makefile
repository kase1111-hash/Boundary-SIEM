.PHONY: all build test run clean lint fmt deps security security-report ci

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
BINARY_TUI=boundary-siem

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
build: build-ingest build-tui

## build-ingest: Build the ingest service
build-ingest:
	mkdir -p $(BIN_DIR)
	$(GOBUILD) $(BUILD_FLAGS) -o $(BIN_DIR)/$(BINARY_INGEST) $(CMD_DIR)/siem-ingest

## build-tui: Build the TUI application
build-tui:
	mkdir -p $(BIN_DIR)
	$(GOBUILD) $(BUILD_FLAGS) -o $(BIN_DIR)/$(BINARY_TUI) $(CMD_DIR)/boundary-siem

## run: Run the ingest service
run:
	$(GORUN) $(CMD_DIR)/siem-ingest/main.go

## run-tui: Run the TUI application
run-tui:
	$(GORUN) $(CMD_DIR)/boundary-siem/main.go

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
	rm -f security-report.json security-report.html

## docker-build: Build Docker image
docker-build:
	docker build -t boundary-siem/ingest:latest -f Dockerfile.ingest .

## security: Run security scanners (gosec)
security:
	@if command -v gosec >/dev/null 2>&1; then \
		echo "Running gosec security scanner..."; \
		gosec -fmt=text -severity=medium ./...; \
	else \
		echo "gosec not installed. Install with: go install github.com/securego/gosec/v2/cmd/gosec@latest"; \
		exit 1; \
	fi

## security-report: Run security scanners with detailed report
security-report:
	@if command -v gosec >/dev/null 2>&1; then \
		echo "Running gosec security scanner..."; \
		gosec -fmt=json -out=security-report.json ./... || true; \
		gosec -fmt=html -out=security-report.html ./... || true; \
		echo "Security reports generated: security-report.json, security-report.html"; \
	else \
		echo "gosec not installed. Install with: go install github.com/securego/gosec/v2/cmd/gosec@latest"; \
		exit 1; \
	fi

## ci: Run all CI checks (lint, security, test)
ci: lint security test
	@echo "All CI checks passed!"

## help: Show this help
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^## ' Makefile | sed 's/## /  /'
