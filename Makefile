# Trust Infrastructure — dev tasks.
# Windows users without `make`: use ./tasks.ps1 <target> (same target names).

SVC_DIR   := services/authorize-svc
COMPOSE   := docker compose -f deploy/docker-compose.yml
VERSION   ?= dev
COMMIT    ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE      ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS   := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: help up down logs run build test tidy fmt vet \
        gen-ts test-contracts test-python test-ts docs test-all

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-10s %s\n", $$1, $$2}'

up: ## Start Postgres 15 + Redis 7 + authorize-svc (one command)
	$(COMPOSE) up -d --build

down: ## Stop the local stack
	$(COMPOSE) down

logs: ## Tail service logs
	$(COMPOSE) logs -f

run: ## Run authorize-svc locally (expects PG+Redis reachable; try `make up` first)
	cd $(SVC_DIR) && go run -ldflags="$(LDFLAGS)" ./cmd/authorize-svc

build: ## Build the authorize-svc binary
	cd $(SVC_DIR) && go build -ldflags="$(LDFLAGS)" -o bin/authorize-svc ./cmd/authorize-svc

test: ## Run tests
	cd $(SVC_DIR) && go test ./...

tidy: ## Sync go.mod/go.sum
	cd $(SVC_DIR) && go mod tidy

fmt: ## Format Go code
	cd $(SVC_DIR) && gofmt -w .

vet: ## Static checks
	cd $(SVC_DIR) && go vet ./...

gen-ts: ## Regenerate TypeScript contract types from /contracts schemas
	node contracts/tools/gen-ts.mjs

test-contracts: ## Validate contracts (schemas+examples+OpenAPI) and the generated Go types
	python contracts/tools/validate.py
	cd contracts/gen/go && go test ./...

test-python: ## Test the Python SDK
	cd sdks/python && python -m pytest -q

test-ts: ## Build + test the TypeScript SDK
	cd sdks/ts && npm install && npm run build && npm test

docs: ## Build the docs site (API reference generated from the OpenAPI spec)
	cd docs-site && npm install && npm run build

test-all: test test-contracts test-python test-ts ## Run every test suite in the repo
