# Everything runs inside the AlmaLinux 9 container (the daemon's target OS),
# so no host toolchain is required beyond podman.
DEV := ./scripts/dev.sh

.PHONY: help image rig-image build release test clippy fmt fmt-check deny check integration rpm acceptance acceptance-destroy clean bench coverage traceability

help:
	@echo "make image        build the AlmaLinux 9 dev/test image"
	@echo "make build        debug build"
	@echo "make release      release build (target/release/oxpanel-daemon)"
	@echo "make test         unit + gRPC-over-UDS tests (fake OS)"
	@echo "make clippy       clippy, pedantic, warnings are errors"
	@echo "make fmt          rustfmt in place"
	@echo "make deny         cargo-deny: advisories, licenses, bans"
	@echo "make check        fmt-check + clippy + test + deny + traceability"
	@echo "make traceability every FEATURES.md row maps to tests that exist (docs/traceability.map)"
	@echo "make bench        engine benchmark against the fake OS (ARGS=\"--tenants 1000,10000 --vhosts 5000\"); not part of check"
	@echo "make coverage     line coverage of oxpanel-daemon (cargo-llvm-cov; run make image once first)"
	@echo "make integration  real root integration test in a systemd container"
	@echo "make rpm          build the RPM from the working tree into dist/rpms/"
	@echo "make acceptance   real AlmaLinux 9 VM (KVM, SELinux enforcing): install RPM, run all phases"
	@echo "                  KEEP=1 keep the VM · PHASES=\"30 60\" subset · SOAK_N=50 · RPM=path · TARGET=user@host"
	@echo "make acceptance-destroy  stop a kept VM"

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

check: fmt-check clippy test deny traceability

traceability:
	./scripts/traceability.sh

# Release build: debug numbers mean nothing. OXPANEL_BENCH_DIR=/dev/shm keeps
# the state on tmpfs (CPU cost without fsync). Output is Markdown for docs/PERFORMANCE.md.
bench:
	$(DEV) cargo run --release -p oxpanel-bench -- $(ARGS)

# Line coverage of the daemon (library + binary) from all its tests. The gate
# (--fail-under-lines) is set in scripts/coverage.sh.
coverage:
	$(DEV) ./scripts/coverage.sh

integration:
	./scripts/integration-test.sh

rig-image:
	podman build -t localhost/oxpanel-rig:alma9 -f tests-acceptance/Containerfile tests-acceptance

rpm:
	$(DEV) ./scripts/build-rpm.sh

acceptance:
	./scripts/acceptance.sh

acceptance-destroy:
	podman rm -f oxpanel-acceptance-vm >/dev/null 2>&1 || true
	@echo "kept VM removed"

clean:
	podman volume rm -f oxpanel-target oxpanel-cargo-registry
	rm -rf dist
