obj-m := spec.o

spec-y := devspec.o

#KERNEL_DIR := /lib/modules/$(shell uname -r)/build
KERNEL_DIR := $(OMNIPLAY_DIR)/linux-lts-quantal-3.5.0

all:
	$(MAKE) -C $(KERNEL_DIR) SUBDIRS=$(shell pwd) modules

clean:
	$(RM) *.o *.a .depend *.d *.ko *.mod.c

install:
	install spec.ko /lib/modules/$(shell uname -r)/kernel/fs/
	/sbin/depmod
