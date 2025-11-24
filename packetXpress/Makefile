# -------------------------
# Paths & variables
# -------------------------
CLANG      ?= clang
BPF_DIR    := bpf
BUILD_DIR  := build

BPF_FLAGS  := -O2 -g -target bpf -D__BPF_TRACING__
BPF_SRCS   := $(wildcard $(BPF_DIR)/*.c)
BPF_OBJS   := $(patsubst $(BPF_DIR)/%.c,$(BUILD_DIR)/%.o,$(BPF_SRCS))
VMLINUX_H  := $(BPF_DIR)/linux_includes/vmlinux.h

# -------------------------
# Default target
# -------------------------
all: bpfs

# -------------------------
# Compile all BPF object files
# -------------------------
bpfs: $(VMLINUX_H) $(BPF_OBJS)
	@echo "✔ All eBPF objects compiled."

# Build rule for each .o
$(BUILD_DIR)/%.o: $(BPF_DIR)/%.c $(VMLINUX_H)
	@mkdir -p $(BUILD_DIR)
	$(CLANG) $(BPF_FLAGS) -c $< -o $@
	@echo "Compiled → $@"


# -------------------------
# Auto-generate vmlinux.h
# -------------------------
$(VMLINUX_H):
	@echo "Generating vmlinux.h ..."
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)
	@echo "✔ vmlinux.h generated."


# -------------------------
# Clean build
# -------------------------
clean:
	@rm -rf $(BUILD_DIR)/*
	@echo "✔ Cleaned build/"


# -------------------------
# Full reset (including vmlinux.h)
# -------------------------
distclean: clean
	@rm -f $(VMLINUX_H)
	@echo "✔ Removed vmlinux.h"


.PHONY: all bpfs clean distclean
