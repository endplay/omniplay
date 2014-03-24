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
	{ 0xb128b138, "module_layout" },
	{ 0xff95a544, "kmalloc_caches" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0xec43ff28, "mem_map" },
	{ 0x27864d57, "memparse" },
	{ 0xc0e82f2d, "single_open" },
	{ 0x6b78c716, "dma_set_mask" },
	{ 0xb0c0a67a, "single_release" },
	{ 0x96c7e43b, "seq_printf" },
	{ 0x3ad70291, "remove_proc_entry" },
	{ 0xee529454, "x86_dma_fallback_dev" },
	{ 0xd35e9659, "mutex_unlock" },
	{ 0x85df9b6c, "strsep" },
	{ 0xa4d730ea, "seq_read" },
	{ 0xe2d5255a, "strcmp" },
	{ 0x50eedeb8, "printk" },
	{ 0x5152e605, "memcmp" },
	{ 0x93645bbc, "vmap" },
	{ 0xb4390f9a, "mcount" },
	{ 0x16305289, "warn_slowpath_null" },
	{ 0xd36d011b, "mutex_lock" },
	{ 0x599b7911, "dma_release_from_coherent" },
	{ 0x754e45f9, "dma_alloc_from_coherent" },
	{ 0x93fca811, "__get_free_pages" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x496d7988, "kmem_cache_alloc_trace" },
	{ 0x4302d0eb, "free_pages" },
	{ 0xbcafc78f, "proc_create_data" },
	{ 0xe4733450, "seq_lseek" },
	{ 0x37a0cba, "kfree" },
	{ 0x94961283, "vunmap" },
	{ 0xa83f5c5a, "dma_supported" },
	{ 0x1fb6d7da, "pci_get_device" },
	{ 0xdf8985e0, "pci_dev_put" },
	{ 0xb742fd7, "simple_strtol" },
	{ 0x362ef408, "_copy_from_user" },
	{ 0x444e490b, "dma_ops" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "2F470542A5C23AD8B7FD70B");
