# SPDX-License-Identifier: GPL-2.0

# ── Installation directories (GNU coding standards) ──────────────────────────

PREFIX          := /usr/local
BINDIR          := $(PREFIX)/bin
MANDIR          := $(PREFIX)/share/man
SYSCONFDIR      := $(PREFIX)/etc
RUNSTATEDIR     := /run
DEFAULT_SOCKDIR := $(RUNSTATEDIR)/bbdd

# ── Directories ───────────────────────────────────────────────────────────────

O   := .output
SRC := src
MAN := man

# ── Tools ─────────────────────────────────────────────────────────────────────

CC        := gcc
CLANG     := clang
LLVM_STRIP := llvm-strip
BPFTOOL   := bpftool
PANDOC    := pandoc
GCOVR     := gcovr
INSTALL   := install

# ── Flags ─────────────────────────────────────────────────────────────────────

PKG_CFLAGS := $(shell pkg-config --cflags libbpf json-c libmnl)
PKG_LIBS   := $(shell pkg-config --libs   libbpf json-c libmnl)

WARN_CFLAGS := -Wall -Wextra -Wmissing-declarations
CFLAGS       = -g -O2 $(WARN_CFLAGS)
LDFLAGS     :=

ifeq ($(COVERAGE),1)
CFLAGS  += --coverage
LDFLAGS += --coverage
endif

# ── sed substitutions applied to all .in files ────────────────────────────────

SED_SUBST := \
    -e 's|@BINDIR@|$(BINDIR)|g'                   \
    -e 's|@SYSCONFDIR@|$(SYSCONFDIR)|g'           \
    -e 's|@RUNSTATEDIR@|$(RUNSTATEDIR)|g'         \
    -e 's|@DEFAULT_SOCKDIR@|$(DEFAULT_SOCKDIR)|g'

# ── C sources, objects, dependency files ─────────────────────────────────────

SRCS := $(filter-out $(SRC)/bbdd-prog.bpf.c, $(wildcard $(SRC)/*.c))
OBJS := $(patsubst $(SRC)/%.c, $(O)/%.o, $(SRCS))
DEPS := $(patsubst $(SRC)/%.c, $(O)/%.dep, $(SRCS))

# ── BPF ───────────────────────────────────────────────────────────────────────

BPF_SRC  := $(SRC)/bbdd-prog.bpf.c
BPF_OBJ  := $(O)/bbdd-prog.bpf.o
BPF_SKEL := $(O)/bbdd-prog.skel.h
VMLINUX  := $(O)/vmlinux.h

# ── Generated config header ───────────────────────────────────────────────────

CONFIG_H := $(O)/config.h

# ── Man pages ─────────────────────────────────────────────────────────────────

MAN_SRCS  := $(wildcard $(MAN)/*.md.in)
MAN_MDS   := $(patsubst $(MAN)/%.md.in, $(O)/man/%.md, $(MAN_SRCS))
MAN_PAGES := $(patsubst $(MAN)/%.md.in, $(O)/man/%,    $(MAN_SRCS))

# ── Binary ────────────────────────────────────────────────────────────────────

BINARY := $(O)/bbdd

# ── Top-level targets ─────────────────────────────────────────────────────────

.PHONY: all clean install coverage

all: $(BINARY) $(MAN_PAGES)

# ── Output directories ────────────────────────────────────────────────────────

$(O) $(O)/man:
	mkdir -p $@

# ── vmlinux.h ─────────────────────────────────────────────────────────────────

$(VMLINUX): | $(O)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# ── BPF program ───────────────────────────────────────────────────────────────

$(BPF_OBJ): $(BPF_SRC) $(VMLINUX) | $(O)
	$(CLANG) -target bpf -O2 -g \
		$(PKG_CFLAGS) -I$(O) -I$(SRC) \
		-c $< -o $@
	$(LLVM_STRIP) -g $@

$(BPF_SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< name bbdd_prog > $@

# ── config.h ──────────────────────────────────────────────────────────────────

$(CONFIG_H): $(SRC)/config.h.in | $(O)
	sed $(SED_SUBST) $< > $@

# ── C compilation ─────────────────────────────────────────────────────────────
# BPF skeleton and config.h are explicit prerequisites so they are generated
# before any source file is compiled, making them available to the compiler
# and to the initial dependency scan.

$(O)/%.o: $(SRC)/%.c $(BPF_SKEL) $(CONFIG_H) | $(O)
	$(CC) $(CFLAGS) $(PKG_CFLAGS) -I$(O) -I$(SRC) \
		-MMD -MF $(O)/$*.dep -MT $@ \
		-c $< -o $@

-include $(DEPS)

# ── Linking ───────────────────────────────────────────────────────────────────

$(BINARY): $(OBJS)
	$(CC) $(LDFLAGS) $^ $(PKG_LIBS) -o $@

# ── Man pages ─────────────────────────────────────────────────────────────────

$(O)/man/%.md: $(MAN)/%.md.in | $(O)/man
	sed $(SED_SUBST) $< > $@

$(O)/man/%: $(O)/man/%.md
	$(PANDOC) -s -t man $< -o $@

# ── Install ───────────────────────────────────────────────────────────────────

install: all
	$(INSTALL) -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 755 $(BINARY) $(DESTDIR)$(BINDIR)/bbdd
	$(INSTALL) -d $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -m 644 $(MAN_PAGES) $(DESTDIR)$(MANDIR)/man8/

# ── Coverage ──────────────────────────────────────────────────────────────────
# Build with COVERAGE=1, run tests, then invoke this target.

coverage:
	mkdir -p $(O)/coverage
	$(GCOVR) -r $(SRC) --object-directory $(O) \
		--html-details $(O)/coverage/index.html

# ── Clean ─────────────────────────────────────────────────────────────────────

clean:
	rm -rf $(O)
