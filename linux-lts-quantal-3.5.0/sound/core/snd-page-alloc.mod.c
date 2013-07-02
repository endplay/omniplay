#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

MODULE_INFO(intree, "Y");

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xee584c90, "module_layout" },
	{ 0x440a4045, "kmalloc_caches" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0xfc9c80e4, "mem_map" },
	{ 0x27864d57, "memparse" },
	{ 0x231f39b0, "single_open" },
	{ 0x24d52bf2, "dma_set_mask" },
	{ 0x94546d8c, "single_release" },
	{ 0x96c7e43b, "seq_printf" },
	{ 0x88ef4b8, "remove_proc_entry" },
	{ 0x91095cab, "x86_dma_fallback_dev" },
	{ 0x6339a8bc, "mutex_unlock" },
	{ 0x85df9b6c, "strsep" },
	{ 0x3f81ddad, "seq_read" },
	{ 0xe2d5255a, "strcmp" },
	{ 0x50eedeb8, "printk" },
	{ 0x5152e605, "memcmp" },
	{ 0x51611843, "vmap" },
	{ 0xb4390f9a, "mcount" },
	{ 0x16305289, "warn_slowpath_null" },
	{ 0xcf510c4a, "mutex_lock" },
	{ 0x599b7911, "dma_release_from_coherent" },
	{ 0x754e45f9, "dma_alloc_from_coherent" },
	{ 0x93fca811, "__get_free_pages" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x7807eace, "kmem_cache_alloc_trace" },
	{ 0x4302d0eb, "free_pages" },
	{ 0xdf420b68, "proc_create_data" },
	{ 0x65a37537, "seq_lseek" },
	{ 0x37a0cba, "kfree" },
	{ 0x94961283, "vunmap" },
	{ 0x103fba37, "dma_supported" },
	{ 0x1fb6d7da, "pci_get_device" },
	{ 0x4a646cd0, "pci_dev_put" },
	{ 0xb742fd7, "simple_strtol" },
	{ 0x362ef408, "_copy_from_user" },
	{ 0x31944a28, "dma_ops" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "2F470542A5C23AD8B7FD70B");
