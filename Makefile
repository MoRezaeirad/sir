.PHONY: build test test-go test-rust test-race coverage check public-contract platform-contract replay bench bench-check contributor-check install clean lint verify verify-release sbom audit smoke-test harness provider-validate kernel-parity sir-core

# Toolchain versions — keep in sync with .github/workflows/ci.yml
RUST_VERSION ?= 1.94.0
GO_VERSION   ?= 1.25.11
REPLAY_ARGS  ?=
BENCH_ARGS   ?= -run '^$$' -bench . -benchmem
RELEASE_TAG  ?=
RELEASE_DIR  ?= ./verify-release
INSTALL_DIR  ?= $(HOME)/.local/bin

# Build flags for reproducibility and security
CARGO_FLAGS  = --release --locked
CARGO_ENV    = CARGO_INCREMENTAL=0
GO_BUILD     = CGO_ENABLED=0 go build -trimpath -ldflags="-s -w"

build:
	$(CARGO_ENV) cargo build $(CARGO_FLAGS)
	mkdir -p bin
	$(GO_BUILD) -o bin/sir ./cmd/sir

# v2 Rust kernel
sir-core:
	$(CARGO_ENV) cargo build --release -p sir-core

# v2 kernel parity: Go and Rust must agree on all harness cases.
# Depends on build so both sir-core-eval and bin/sir are always fresh.
kernel-parity: build
	bin/sir harness run --engine both harness/fixtures/cases

# v2 capture-tier honesty gate: capture score must not regress below fixture score.
# Fails CI if any case's capture result is weaker than its fixture claim.
# "fixture says enforces but capture says detects" → bug in fixture.
harness-capture: build
	bin/sir harness run --tier capture harness/fixtures/cases

# Regenerate evasion capture.json files from REAL process reproductions
# (item 12). Each evasion is reproduced with harmless commands and its flags are
# derived from genuine observation (real pgid divergence, real stripped span,
# etc.). Run after changing the generator; the capture tier then scores reality.
harness-capture-generate: build
	bin/sir harness capture-generate --write harness/fixtures/cases

# v2 provider SDK targets
harness:
	bin/sir harness run harness/fixtures/cases

provider-validate:
	bin/sir provider validate examples/providers/toy-signal/provider.yaml
	bin/sir provider validate examples/providers/sandbox-provider-stub/provider.yaml
	bin/sir provider validate examples/providers/noop-effect/provider.yaml

# Run only Go tests
test-go:
	go test ./... -v -count=1

# Run only Rust tests
test-rust:
	cargo test --locked

# Run all tests (Rust + Go)
test: test-rust test-go

# Run tests with race detector
test-race:
	go test -race ./... -count=1
	cargo test --locked

# Coverage report
coverage:
	go test ./... -coverprofile=coverage.out -covermode=atomic
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Run the full verification suite (lint + test + verify + kernel parity).
# kernel-parity proves Rust and Go agree on all harness cases.
check: public-contract platform-contract lint test verify kernel-parity

public-contract:
	go test ./cmd/sir -run TestPublicContractParity

platform-contract:
	python3 scripts/check_os_coverage.py

replay:
	mkdir -p bin
	go build -o bin/sir ./cmd/sir
	bash testdata/run_fixtures.sh $(REPLAY_ARGS)

bench:
	go test ./cmd/sir ./pkg/core ./pkg/hooks ./pkg/ledger ./pkg/session ./pkg/runtime ./pkg/mcp ./pkg/telemetry $(BENCH_ARGS)

bench-check:
	python3 scripts/check_bench_budget.py

# Friction budget: assert a normal-coding session is silent (0 prompts/0 blocks)
# and the everyday-command verdicts hold (FRICTION-1 / BUDGET-1). This is the
# quantified "invisible on normal coding" SLO — run it after any policy change.
friction-bench:
	go test ./pkg/hooks/ -run 'TestFrictionBenchmark_NormalCodingIsSilent|TestBlockingBudget' -count=1 -v

contributor-check:
	bash scripts/check_review_context.sh

install: build
	mkdir -p "$(INSTALL_DIR)"
	cp target/release/mister-core "$(INSTALL_DIR)/"
	cp target/release/sir-core-eval "$(INSTALL_DIR)/"
	cp bin/sir "$(INSTALL_DIR)/"
	chmod 750 "$(INSTALL_DIR)/mister-core" "$(INSTALL_DIR)/sir-core-eval" "$(INSTALL_DIR)/sir"
	@if [ "$$(uname -s)" = "Darwin" ] && command -v codesign >/dev/null 2>&1; then \
		codesign --sign - "$(INSTALL_DIR)/sir"; \
		codesign --sign - "$(INSTALL_DIR)/sir-core-eval"; \
		codesign --sign - "$(INSTALL_DIR)/mister-core"; \
	fi
	@VERSION=$$(sed -n 's/^const Version = "\(.*\)"/\1/p' cmd/sir/version.go); \
	if command -v sha256sum >/dev/null 2>&1; then \
		SIR_SHA=$$(sha256sum "$(INSTALL_DIR)/sir" | awk '{print $$1}'); \
		SCE_SHA=$$(sha256sum "$(INSTALL_DIR)/sir-core-eval" | awk '{print $$1}'); \
		MC_SHA=$$(sha256sum "$(INSTALL_DIR)/mister-core" | awk '{print $$1}'); \
	else \
		SIR_SHA=$$(shasum -a 256 "$(INSTALL_DIR)/sir" | awk '{print $$1}'); \
		SCE_SHA=$$(shasum -a 256 "$(INSTALL_DIR)/sir-core-eval" | awk '{print $$1}'); \
		MC_SHA=$$(shasum -a 256 "$(INSTALL_DIR)/mister-core" | awk '{print $$1}'); \
	fi; \
	MANIFEST_DIR="$$HOME/.sir"; \
	mkdir -p "$$MANIFEST_DIR"; \
	printf '{\n  "version": "%s",\n  "installed_at": "%s",\n  "install_method": "source",\n  "sir_path": "%s",\n  "sir_sha256": "%s",\n  "sir_core_eval_path": "%s",\n  "sir_core_eval_sha256": "%s",\n  "mister_core_path": "%s",\n  "mister_core_sha256": "%s",\n  "mister_core_legacy": true\n}\n' \
		"$$VERSION" "$$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
		"$(INSTALL_DIR)/sir" "$$SIR_SHA" \
		"$(INSTALL_DIR)/sir-core-eval" "$$SCE_SHA" \
		"$(INSTALL_DIR)/mister-core" "$$MC_SHA" \
		> "$$MANIFEST_DIR/binary-manifest.json"; \
	chmod 600 "$$MANIFEST_DIR/binary-manifest.json"; \
	touch "$$MANIFEST_DIR/.manifest-expected"; \
	chmod 600 "$$MANIFEST_DIR/.manifest-expected"
	@echo "Installed: sir, sir-core-eval (v2 decision kernel), mister-core (v1 legacy)"

clean:
	cargo clean
	rm -rf bin/
	rm -f CHECKSUMS.sha256 CHECKSUMS.sha512 sbom-sir.cdx.json

lint:
	cargo clippy --locked -- -D warnings
	go vet ./...

# Supply chain verification
verify: lint
	@echo "=== Verifying zero external Rust dependencies ==="
	@APPROVED="mister-core mister-shared sir-core"; \
	LOCK_PKGS=$$(grep '^name = ' Cargo.lock | awk '{print $$3}' | tr -d '"' | sort); \
	for pkg in $$LOCK_PKGS; do \
		if ! echo "$$APPROVED" | grep -qw "$$pkg"; then \
			echo "FATAL: Unapproved package in Cargo.lock: $$pkg"; \
			echo "Approved: mister-core (v1 legacy), mister-shared (v1 shared), sir-core (v2 decision kernel)"; \
			exit 1; \
		fi; \
	done; \
	echo "OK: Cargo.lock contains approved packages: $$LOCK_PKGS"
	@echo ""
	@echo "=== Running cargo-deny ==="
	cargo deny check
	@echo ""
	@echo "=== Running Go supply chain checks ==="
	bash scripts/go-supply-chain.sh
	@echo ""
	@echo "=== Generating checksums ==="
	bash scripts/checksum.sh ./bin 2>/dev/null || bash scripts/checksum.sh target/release 2>/dev/null || echo "No artifacts to checksum (run 'make build' first)"

verify-release:
	bash scripts/verify-release.sh "$(RELEASE_TAG)" "$(RELEASE_DIR)"

# SBOM generation
sbom:
	@command -v syft >/dev/null 2>&1 || { echo "Install syft: https://github.com/anchore/syft"; exit 1; }
	syft dir:. -o cyclonedx-json > sbom-sir.cdx.json
	@echo "SBOM written to sbom-sir.cdx.json"

# Security audit
audit:
	@echo "=== Cargo audit ==="
	@if command -v cargo-audit >/dev/null 2>&1; then \
		cargo audit; \
	else \
		echo "cargo-audit not installed (cargo install cargo-audit)"; \
	fi
	@echo ""
	@echo "=== govulncheck ==="
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	else \
		echo "govulncheck not installed (go install golang.org/x/vuln/cmd/govulncheck@v1.1.4)"; \
	fi
	@echo ""
	@echo "=== cargo-deny ==="
	cargo deny check

# Real smoke tests against Claude Code (requires claude CLI authenticated)
smoke-test: build install
	@command -v claude >/dev/null 2>&1 || { echo "Claude Code not installed. Install: npm install -g @anthropic-ai/claude-code"; exit 1; }
	bash scripts/smoke-test.sh
