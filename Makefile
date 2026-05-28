BPFTOOL ?= bpftool
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
LIBBPF ?= -lbpf
LIBMNL ?= -lmnl
COVERAGE ?= 0

ifeq ($(V),1)
	Q =
	NQ = @
	msg =
else
	Q = @
	NQ =
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

OUTPUT := .output
INCLUDES := -I $(OUTPUT)

WARN_CFLAGS = -Wall -Wunused
CFLAGS := -g $(WARN_CFLAGS)

ifeq ($(COVERAGE),1)
	CFLAGS += --coverage
	LDFLAGS += --coverage
endif

APPS := bbdd
bbdd-OBJECTS :=					\
	$(OUTPUT)/bbdd.o			\
	$(OUTPUT)/bbdd-bfdd.o			\
	$(OUTPUT)/bbdd-bpf.o			\
	$(OUTPUT)/bbdd-br.o			\
	$(OUTPUT)/bbdd-c.o			\
	$(OUTPUT)/bbdd-d.o			\
	$(OUTPUT)/bbdd-jrpc.o			\
	$(OUTPUT)/bbdd-mon.o			\
	$(OUTPUT)/bbdd-nl.o			\
	$(OUTPUT)/bbdd-poll.o			\
	$(OUTPUT)/bbdd-sess.o			\
	$(OUTPUT)/bbdd-sock.o			\
	$(OUTPUT)/bbdd-util.o			\
	$(OUTPUT)/bbdd-util.o			\
	$(OUTPUT)/bfddp.o			\
	#
SYSTEMD_UNITS :=				\
	$(OUTPUT)/bbdd.service			\
	#
MAN_PAGES :=					\
	#
EXTRA_CLEAN :=					\
	$(OUTPUT)/config.h			\
	$(OUTPUT)/bbdd-prog.bpf.o		\
	$(OUTPUT)/bbdd-prog.skel.h		\
	#
EXTRA_DEPS :=					\
	$(OUTPUT)/bbdd-prog.bpf.o		\
	#

# Files that need to be in place before dependencies can be parsed.
DEP_DEPS :=					\
	$(OUTPUT)/config.h			\
	$(OUTPUT)/bbdd-prog.skel.h		\
	$(OUTPUT)/vmlinux.h
	#

# N.B. sort also makes the list unique.
ALL_OBJECTS := $(sort $(foreach app,$(APPS),$($(app)-OBJECTS)) $(EXTRA_DEPS))
ALL_DEPS := $(ALL_OBJECTS:%.o=%.dep)
OUTPUT_DIRS := $(sort $(dir $(ALL_OBJECTS)))

BUILT := $(APPS) $(SYSTEMD_UNITS) $(MAN_PAGES)

PREFIX = /usr/local
EXEC_PREFIX = $(PREFIX)
BINDIR = $(EXEC_PREFIX)/bin
DATAROOTDIR = $(PREFIX)/share
DATADIR = $(DATAROOTDIR)
SYSCONFDIR = $(PREFIX)/etc
LOCALSTATEDIR = $(PREFIX)/var
RUNSTATEDIR = $(LOCALSTATEDIR)/run
DOCDIR = $(DATAROOTDIR)/doc/$(PACKAGE)
MANDIR = $(DATAROOTDIR)/man
MAN8DIR = $(MANDIR)/man8
SYSTEMDSYSTEMUNITDIR = $(shell pkgconf --variable=systemdsystemunitdir systemd)
DESTDIR =
VAR_SUBSTITUTIONS = 				\
	s|@BINDIR@|$(BINDIR)|g;			\
	s|@SYSCONFDIR@|$(SYSCONFDIR)|g;		\
	s|@RUNSTATEDIR@|$(RUNSTATEDIR)|g;	\
	s|@DEFAULT_SOCKDIR@|$(RUNSTATEDIR)|g;	\
	#

.PHONY: all
all: $(BUILT)

.PHONY: clean
clean:
	rm -Rf $(OUTPUT)

.PHONY: doc
doc: $(MAN_PAGES)

.PHONY: $(APPS)
$(APPS): %: $(OUTPUT)/%

.PHONY: install
install: $(BUILT)
	echo xxx no install xxx

%/:
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

$(OUTPUT)/bbdd: LDFLAGS += $(shell pkgconf --libs libelf json-c libsystemd \
				libnl-3.0 libnl-genl-3.0)
$(OUTPUT)/bbdd: $(bbdd-OBJECTS) $(LIBBPF) $(LIBMNL)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $^ $(LDFLAGS) -lz -o $@

$(OUTPUT)/%.o: %.c | $(OUTPUT_DIRS)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(OUTPUT)/%.dep: %.c | $(OUTPUT_DIRS) $(DEP_DEPS)
	$(call msg,DEP,$@)
	$(Q)$(CC) -MM $(CFLAGS) -MT '$(@:%.dep=%.o) $@' $(INCLUDES) $< -o $@

$(OUTPUT)/%: %.in | $(OUTPUT_DIRS)
	$(call msg,SED,$*)
	$(Q)sed -e '$(VAR_SUBSTITUTIONS)' $< > $@
	$(Q)chmod --reference=$< $@

$(OUTPUT)/vmlinux.h: /sys/kernel/btf/vmlinux
	$(Q)$(BPFTOOL) btf dump file $< format c > $@

.PRECIOUS: $(OUTPUT)/%.bpf.o
$(OUTPUT)/%.bpf.o: %.bpf.c bbdd.h $(OUTPUT)/vmlinux.h
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(WARN_CFLAGS) -c $< -o $@
	$(Q)$(LLVM_STRIP) -g $@ # strip useless DWARF info

$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< name bbdd_prog > $@

$(MAN_PAGES): $(OUTPUT)/%: %.md | $(OUTPUT_DIRS)
	pandoc --standalone --to man $< -o $@

test: $(BUILT)
	tests/run.sh

ifeq ($(COVERAGE),1)
coverage: $(OUTPUT)/coverage/ | $(OUTPUT_DIRS)
	gcovr --html-nested --output $(OUTPUT)/coverage/bbdd.html

coverage-clean:
	rm -f $(OUTPUT)/*.gcda
endif

-include $(ALL_DEPS)
