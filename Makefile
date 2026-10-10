# On macOS, re-sign so the signature carries the bundle ID from the embedded
# macos/Info.plist (see build.rs). Without it, macOS hides the ARP table.
SIGN = $(if $(filter Darwin,$(shell uname)),codesign --force --sign - $(1),@true)

.PHONY: build install

build:
	cargo build --release
	$(call SIGN,target/release/giddy)

install:
	cargo install --path .
	$(call SIGN,$(or $(CARGO_HOME),$(HOME)/.cargo)/bin/giddy)
