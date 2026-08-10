BINARY  ?= mitmania
VERSION ?= stripped
OUTPUT  ?= bin/$(BINARY)

.PHONY: build clean docs docs-test

build:
	CGO_ENABLED=0 go build -ldflags "-w -s -X main.version=$(VERSION) -buildid= -extldflags=static" -buildvcs=false -a -trimpath -o $(OUTPUT) ./cmd/$(BINARY)

clean:
	rm -rf bin

docs:
	mkdocs serve

docs-test:
	go test ./internal/rules
	mkdocs build --strict
