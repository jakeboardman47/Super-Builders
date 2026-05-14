# SPDX-License-Identifier: GPL-2.0
#
# Out-of-tree build wrapper for redirfs-lite.
#
# Usage:
#   make KDIR=/path/to/kernel/source ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- \
#        LLVM=1 CC=clang
#
# In Super-Builders CI, KDIR is the synced common/ directory after Bazel
# produces the .config and headers (kernel_aarch64_dist).

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(CURDIR)
ARCH ?= arm64

.PHONY: all clean modules_install

all:
	$(MAKE) -C $(KDIR) M=$(PWD)/src ARCH=$(ARCH) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD)/src ARCH=$(ARCH) clean
	rm -f src/*.ko src/.*.cmd src/Module.symvers src/modules.order

modules_install:
	$(MAKE) -C $(KDIR) M=$(PWD)/src ARCH=$(ARCH) modules_install
