.PHONY: all update lint run build build-in-docker install docker run-agent build-agent build-agent-in-docker docker-agent

all: update run

update:
	@go mod tidy \
		&& go mod vendor

lint:
	@golangci-lint run ./...

test:
	@go test ./... -coverprofile=tmp/coverage.out

coverage:
	@go tool cover -html=tmp/coverage.out

mock:
	@mockery --name ".*" --case underscore --exported --with-expecter --output ./tmp/mocks --dir $(DIR) \
		&& rm -rf $(DIR)/mocks \
		&& mv tmp/mocks $(DIR)

mockall:
	@mockery --all --keeptree --case underscore --exported --with-expecter --output ./tmp/mocks --dir $(DIR) \
		&& find tmp/mocks -type d -depth -exec bash -c 'rm -rf $(DIR)$${1#tmp/mocks}/mocks && mv $$1 $(DIR)$${1#tmp/mocks}/mocks' _ {} \;

run: update
	@go run ./cmd/relay

build: update
	@go build -o ./tmp/bridgertun-relay ./cmd/relay

build-in-docker:
	@CGO_ENABLED=0 GOOS=$${TARGETOS} GOARCH=$${TARGETARCH} go build -o /tmp/build ./cmd/relay

docker:
	docker build -t lwj5/bridgertun-relay .

run-agent:
	@go run ./cmd/agent $(ARGS)
	
build-agent: update
	@go build -o ./tmp/bridgertun-agent ./cmd/agent

build-agent-in-docker:
	@CGO_ENABLED=0 GOOS=$${TARGETOS} GOARCH=$${TARGETARCH} go build -o /tmp/build-agent ./cmd/agent

docker-agent:
	docker build -f Dockerfile.agent -t lwj5/bridgertun-agent .

compose-up:
	docker compose up -d

compose-down:
	docker compose down -v
