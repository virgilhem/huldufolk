TEST?=$(patsubst test/%.bats,%,$(wildcard test/*.bats))

CARGO_FLAGS := --target x86_64-unknown-linux-musl --release
BIN_PATH := target/x86_64-unknown-linux-musl/release/usermode-helper

ifdef DEBUG
	CARGO_FLAGS :=
	BIN_PATH := target/debug/usermode-helper
endif

.PHONY: all
all:
# rustfmt src/*
	cargo build $(CARGO_FLAGS)

.PHONY: check
check:
	# need to force a rebuild for DEFAULT_CONFIG_PATH
	cargo clean -p usermode-helper
	DEFAULT_CONFIG_PATH=./usermode-helper.conf cargo build $(CARGO_FLAGS)
	UMH_BIN=$(abspath $(BIN_PATH)) bats -t $(patsubst %,test/%.bats,$(TEST))

.PHONY: check-dmesg
check-dmesg:
	sudo UMH_BIN=$(abspath $(BIN_PATH)) bats -t test/dmesg.bats

.PHONY: clean
clean:
	cargo clean
