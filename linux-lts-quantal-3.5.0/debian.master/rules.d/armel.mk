human_arch	= ARM (soft float)
build_arch	= arm
header_arch	= arm
defconfig	= defconfig
flavours	= omap
build_image	= zImage
kernel_file	= arch/$(build_arch)/boot/zImage
install_file	= vmlinuz
no_dumpfile = true

loader		= grub
