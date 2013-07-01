human_arch	= PowerPC (64 bit userspace)
build_arch	= powerpc
header_arch	= $(build_arch)
defconfig	= ppc64_defconfig
flavours	= powerpc64-smp
build_image	= vmlinux
kernel_file	= $(build_image)
install_file	= $(build_image)

loader		= yaboot

custom_flavours	=

no_dumpfile = true
skipdbg		= true
skipabi		= true
skipmodule	= true

family=ubuntu
