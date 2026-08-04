APP := homefleet
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
DIST := dist

.PHONY: build test vet check clean release-local

build:
	mkdir -p bin
	go build -ldflags "$(LDFLAGS)" -o bin/$(APP) ./cmd/homefleet

test:
	go test ./...

vet:
	go vet ./...

check: vet test build

clean:
	rm -rf bin $(DIST)

release-local: clean
	mkdir -p $(DIST)
	# Linux
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(APP)_linux_amd64 ./cmd/homefleet
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(APP)_linux_arm64 ./cmd/homefleet
	# macOS Big Sur+
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 MACOSX_DEPLOYMENT_TARGET=11.0 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(APP)_darwin_amd64 ./cmd/homefleet
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 MACOSX_DEPLOYMENT_TARGET=11.0 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(APP)_darwin_arm64 ./cmd/homefleet
	# Windows
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(APP)_windows_amd64.exe ./cmd/homefleet
	cd $(DIST) && sha256sum $(APP)_* > SHA256SUMS
