BINARY   ?= mitmania
VERSION  ?= stripped
BIN_DIR  ?= bin
DIST_DIR ?= dist

RELEASE_GOOS = aix darwin dragonfly freebsd illumos linux netbsd openbsd solaris windows
GO_DIST_TARGETS = $(subst /,-,$(shell go tool dist list))
RELEASE_TARGETS = $(patsubst %-arm,%-armv7,$(foreach os,$(RELEASE_GOOS),$(filter $(os)-%,$(GO_DIST_TARGETS))))

target_os = $(word 1,$(subst -, ,$(1)))
target_arch = $(word 2,$(subst -, ,$(1)))
target_goarch = $(patsubst armv7,arm,$(call target_arch,$(1)))
target_binary = $(BIN_DIR)/$(BINARY)-$(1)$(if $(filter windows-%,$(1)),.exe)
target_archive = $(DIST_DIR)/$(BINARY)-$(1).$(if $(filter windows-%,$(1)),zip,tar.gz)

RELEASE_BINARIES = $(foreach target,$(RELEASE_TARGETS),$(call target_binary,$(target)))
RELEASE_ARCHIVES = $(foreach target,$(RELEASE_TARGETS),$(call target_archive,$(target)))

NATIVE_TARGET = $(patsubst %-arm,%-armv7,$(shell go env GOOS)-$(shell go env GOARCH))
NATIVE_BINARY = $(call target_binary,$(NATIVE_TARGET))

DEB_TARGETS = linux-amd64 linux-arm64 linux-armv7 linux-386 linux-ppc64le linux-riscv64 linux-s390x
DEB_ARCHES  = amd64 arm64 armhf i386 ppc64el riscv64 s390x

DEB_ARCH_linux-amd64   = amd64
DEB_ARCH_linux-arm64   = arm64
DEB_ARCH_linux-armv7   = armhf
DEB_ARCH_linux-386     = i386
DEB_ARCH_linux-ppc64le = ppc64el
DEB_ARCH_linux-riscv64 = riscv64
DEB_ARCH_linux-s390x   = s390x

DEB_TARGET_amd64   = linux-amd64
DEB_TARGET_arm64   = linux-arm64
DEB_TARGET_armhf   = linux-armv7
DEB_TARGET_i386    = linux-386
DEB_TARGET_ppc64el = linux-ppc64le
DEB_TARGET_riscv64 = linux-riscv64
DEB_TARGET_s390x   = linux-s390x

TARGET ?= $(NATIVE_TARGET)
TARGET_BINARY = $(call target_binary,$(TARGET))
TARGET_ARCHIVE = $(call target_archive,$(TARGET))

DEB_ARCH = $(DEB_ARCH_$(TARGET))
DEB_VERSION = $(patsubst v%,%,$(VERSION))-1
DEB_PACKAGE = $(DIST_DIR)/$(BINARY)_$(DEB_VERSION)_$(DEB_ARCH).deb
DEB_PACKAGES = $(foreach arch,$(DEB_ARCHES),$(DIST_DIR)/$(BINARY)_$(DEB_VERSION)_$(arch).deb)

GO_BUILD_INPUTS = $(shell find cmd internal -type f -name '*.go') go.mod go.sum Makefile
DEB_INPUTS = \
	packaging/debian/control.in \
	packaging/debian/conffiles \
	packaging/debian/mitmania.default \
	packaging/debian/mitmania.service \
	packaging/debian/postinst \
	packaging/debian/postrm

all: $(RELEASE_BINARIES) $(BIN_DIR)/$(BINARY)

.PHONY: all archive archive-path archives build clean cross-build deb deb-arches deb-targets debs docs docs-test release release-targets

build: $(BIN_DIR)/$(BINARY)

cross-build: $(TARGET_BINARY)

$(BIN_DIR)/$(BINARY): $(NATIVE_BINARY)
	@ln -sfn "$(notdir $<)" "$@"

$(BIN_DIR)/$(BINARY)-windows-%.exe: $(GO_BUILD_INPUTS)
	@mkdir -p "$(@D)"
	CGO_ENABLED=0 GOOS=windows GOARCH="$(call target_goarch,windows-$*)" \
	go build -ldflags "-w -s -X main.version=$(VERSION) -buildid= -extldflags=static" -buildvcs=false -a -trimpath -o "$@" ./cmd/$(BINARY)

$(BIN_DIR)/$(BINARY)-%: $(GO_BUILD_INPUTS)
	@mkdir -p "$(@D)"
	CGO_ENABLED=0 \
	GOOS="$(call target_os,$*)" \
	GOARCH="$(call target_goarch,$*)" $(if $(filter armv7,$(call target_arch,$*)),GOARM=7) \
	go build -ldflags "-w -s -X main.version=$(VERSION) -buildid= -extldflags=static" -buildvcs=false -a -trimpath -o "$@" ./cmd/$(BINARY)

archive: $(TARGET_ARCHIVE)

archives: $(RELEASE_ARCHIVES)

archive-path:
	@printf '%s\n' "$(TARGET_ARCHIVE)"

$(DIST_DIR)/%/$(BINARY): $(BIN_DIR)/$(BINARY)-%
	@mkdir -p "$(@D)"
	cp "$<" "$@"

$(DIST_DIR)/windows-%/$(BINARY).exe: $(BIN_DIR)/$(BINARY)-windows-%.exe
	@mkdir -p "$(@D)"
	cp "$<" "$@"

$(DIST_DIR)/$(BINARY)-%.tar.gz: $(DIST_DIR)/%/$(BINARY)
	@mkdir -p "$(@D)"
	tar -czf "$@" -C "$(dir $<)" "$(notdir $<)"

$(DIST_DIR)/$(BINARY)-windows-%.zip: $(DIST_DIR)/windows-%/$(BINARY).exe
	@mkdir -p "$(@D)"
	@cd "$(dir $<)" && zip -9 "$(abspath $@)" "$(notdir $<)"

deb: $(DEB_PACKAGE)

debs: $(DEB_PACKAGES)

.SECONDEXPANSION:
$(DIST_DIR)/$(BINARY)_$(DEB_VERSION)_%.deb: $$(BIN_DIR)/$$(BINARY)-$$(DEB_TARGET_$$*) $(DEB_INPUTS)
	@set -eu; \
	test -n "$(DEB_TARGET_$*)" || { echo "unsupported Debian architecture: $*" >&2; exit 1; }; \
	case "$(DEB_VERSION)" in [0-9]*) ;; *) echo "VERSION must start with a digit, optionally preceded by v" >&2; exit 1 ;; esac; \
	command -v debx >/dev/null; \
	build_info=$$(go version -m "$<"); \
	binary_os=$$(printf '%s\n' "$$build_info" | awk -F= '/GOOS=/{print $$2; exit}'); \
	binary_arch=$$(printf '%s\n' "$$build_info" | awk -F= '/GOARCH=/{print $$2; exit}'); \
	binary_arm=$$(printf '%s\n' "$$build_info" | awk -F= '/GOARM=/{print $$2; exit}'); \
	test "$$binary_os/$$binary_arch" = "$(call target_os,$(DEB_TARGET_$*))/$(call target_goarch,$(DEB_TARGET_$*))" || { echo "$(DEB_TARGET_$*) does not match binary $$binary_os/$$binary_arch" >&2; exit 1; }; \
	if [ "$(call target_arch,$(DEB_TARGET_$*))" = armv7 ]; then test "$$binary_arm" = 7; fi; \
	mkdir -p "$(@D)"; \
	control_file="$(@D)/.mitmania-control-$*"; \
	package_file="$@.tmp"; \
	trap 'rm -f "$$control_file" "$$package_file"' EXIT HUP INT TERM; \
	installed_size=$$(du -k "$<" | awk '{print $$1}'); \
	sed -e 's/@VERSION@/$(DEB_VERSION)/g' \
	    -e 's/@ARCHITECTURE@/$*/g' \
	    -e "s/@INSTALLED_SIZE@/$$installed_size/g" \
	    packaging/debian/control.in > "$$control_file"; \
	debx pack \
		--control \
			"$$control_file:/control" \
			"packaging/debian/conffiles:/conffiles" \
			"packaging/debian/postinst:/postinst:mode=0755,uid=0,gid=0" \
			"packaging/debian/postrm:/postrm:mode=0755,uid=0,gid=0" \
		--data \
			"$<:/usr/bin/mitmania:mode=0755,uid=0,gid=0" \
			"packaging/debian/mitmania.service:/usr/lib/systemd/system/mitmania.service:mode=0644,uid=0,gid=0" \
			"packaging/debian/mitmania.default:/etc/default/mitmania:mode=0600,uid=0,gid=0" \
		--deb "$$package_file"; \
	mv "$$package_file" "$@"

release: archives debs

release-targets:
	@printf '%s\n' $(RELEASE_TARGETS)

deb-targets:
	@printf '%s\n' $(DEB_TARGETS)

deb-arches:
	@printf '%s\n' $(DEB_ARCHES)

clean:
	rm -rf "$(BIN_DIR)" "$(DIST_DIR)"

docs:
	mkdocs serve

docs-test:
	go test ./internal/rules
	mkdocs build --strict
