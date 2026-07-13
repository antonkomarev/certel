BIN     := bin
VERSION ?= $(shell git describe --tags --always --dirty)

.PHONY: build test vet clean

build:
	mkdir -p $(BIN)
	go build -trimpath -ldflags "-X main.version=$(VERSION)" -o $(BIN)/certel ./cmd/certel
	go build -trimpath -o $(BIN)/notification-sink ./cmd/notification-sink

test:
	go test -race ./...

vet:
	go vet ./...

clean:
	rm -rf $(BIN)
