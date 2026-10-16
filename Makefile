# WGM build helpers. Everything here is plain `go` underneath; see
# docs/INSTALL-FEDORA.md for details.

VERSION ?= 0.1.0
PREFIX  ?= /usr
DESTDIR ?=
GO      ?= go
GOFLAGS ?= -trimpath
LDFLAGS := -X main.version=$(VERSION)
UNITDIR ?= $(PREFIX)/lib/systemd/system
SYSUSERSDIR ?= $(PREFIX)/lib/sysusers.d

.PHONY: all build wgmd wgm-ui test test-root vet fmt-check install uninstall clean vendor-tarball

all: build

build: wgmd wgm-ui

wgmd:
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/wgmd ./cmd/wgmd

wgm-ui:
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/wgm-ui ./cmd/wgm-ui

test:
	$(GO) test ./...

# Network-namespace end-to-end tests (root, isolated; never touches the host
# firewall or VPN configuration).
test-root:
	sudo -E env "PATH=$$PATH" WGM_NETNS_TESTS=1 $(GO) test -count=1 -v -timeout 15m ./tests/netns/

vet:
	$(GO) vet ./...

fmt-check:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; exit 1; }

# Run `make build` as your user first; install only copies files so that
# `sudo make install` does not compile as root.
install:
	@test -x bin/wgmd -a -x bin/wgm-ui || { echo "run 'make build' first"; exit 1; }
	install -Dm0755 bin/wgmd $(DESTDIR)$(PREFIX)/bin/wgmd
	install -Dm0755 bin/wgm-ui $(DESTDIR)$(PREFIX)/bin/wgm-ui
	install -Dm0644 systemd/wgmd.service $(DESTDIR)$(UNITDIR)/wgmd.service
	install -Dm0644 systemd/wgm-killswitch.service $(DESTDIR)$(UNITDIR)/wgm-killswitch.service
	install -Dm0644 packaging/fedora/wgm.sysusers $(DESTDIR)$(SYSUSERSDIR)/wgm.conf
	install -Dm0644 packaging/fedora/io.github.cmerk2021.wgm.desktop $(DESTDIR)$(PREFIX)/share/applications/io.github.cmerk2021.wgm.desktop

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/wgmd $(DESTDIR)$(PREFIX)/bin/wgm-ui \
	  $(DESTDIR)$(UNITDIR)/wgmd.service $(DESTDIR)$(UNITDIR)/wgm-killswitch.service \
	  $(DESTDIR)$(SYSUSERSDIR)/wgm.conf \
	  $(DESTDIR)$(PREFIX)/share/applications/io.github.cmerk2021.wgm.desktop

# Source + vendored dependencies for offline RPM builds.
vendor-tarball:
	rm -rf vendor && $(GO) mod vendor
	tmp=$$(mktemp) && \
	  tar --transform 's,^\./,wgm-$(VERSION)/,' -czf "$$tmp" --exclude=./bin --exclude='*.tar.gz' --exclude-vcs . && \
	  mv "$$tmp" wgm-$(VERSION).tar.gz; status=$$?; rm -rf vendor; exit $$status

clean:
	rm -rf bin vendor wgm-*.tar.gz
