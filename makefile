# Makefile — CyberTrace CTF kernel module
#
# Usage:
#   make              — build ctf_driver.ko against the running kernel
#   make KDIR=<path>  — build against an alternate kernel source tree
#   make clean        — remove all build artefacts
#
# After building:
#   sudo insmod ctf_driver.ko
#   sudo rmmod  ctf_driver
#   dmesg | tail       — check kernel log

# Path to the kernel build tree (default: running kernel)
KDIR ?= /lib/modules/$(shell uname -r)/build

# Module object
obj-m := ctf_driver.o

# Optional: enable DEBUG-level printk messages at build time
# Uncomment the line below to activate pr_debug() output
# ccflags-y += -DDEBUG

# Build target — delegate everything to the kernel build system
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Clean target
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

# Convenience helpers (require root)
load:
	sudo insmod ctf_driver.ko

unload:
	sudo rmmod ctf_driver

log:
	sudo dmesg | grep ctf | tail -20

.PHONY: all clean load unload log
