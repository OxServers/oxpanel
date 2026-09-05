# Everything runs inside the AlmaLinux 9 container (the daemon's target OS),
# so no host toolchain is required beyond podman.
DEV := ./scripts/dev.sh

.PHONY: help image build release test clippy fmt fmt-check deny check integration clean

help:
	@echo "make image        build the AlmaLinux 9 dev/test image"
	@echo "make build        debug build"
	@echo "make release      release build (target/release/oxpanel-daemon)"
	@echo "make test         unit + gRPC-over-UDS tests (fake OS)"
	@echo "make clippy       clippy, pedantic, warnings are errors"
	@echo "make fmt          rustfmt in place"
	@echo "make deny         cargo-deny: advisories, licenses, bans"
	@echo "make check        fmt-check + clippy + test + deny"
	@echo "make integration  real root integration test in a systemd container"

image:
	podman build -t localhost/oxpanel-dev:alma9 -f tests-integration/Containerfile tests-integration

build:
	$(DEV) cargo build --all-targets

release:
	$(DEV) cargo build --release --locked

test:
	$(DEV) cargo test --all-targets

clippy:
	$(DEV) cargo clippy --all-targets --all-features -- -D warnings

fmt:
	$(DEV) cargo fmt --all

fmt-check:
	$(DEV) cargo fmt --all -- --check

deny:
	$(DEV) cargo deny check

check: fmt-check clippy test deny

integration:
	./scripts/integration-test.sh

clean:
	podman volume rm -f oxpanel-target oxpanel-cargo-registry
