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
	{ 0x402b8281, "__request_module" },
	{ 0xff95a544, "kmalloc_caches" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0xd35e9659, "mutex_unlock" },
	{ 0xe2d5255a, "strcmp" },
	{ 0x827e959c, "snd_device_new" },
	{ 0xfc629f82, "__mutex_init" },
	{ 0x50eedeb8, "printk" },
	{ 0xb4390f9a, "mcount" },
	{ 0x73e20c1c, "strlcpy" },
	{ 0xd36d011b, "mutex_lock" },
	{ 0x4b015768, "snd_iprintf" },
	{ 0x496d7988, "kmem_cache_alloc_trace" },
	{ 0x37a0cba, "kfree" },
	{ 0x238cc109, "snd_seq_root" },
	{ 0xeaf57edb, "snd_info_free_entry" },
	{ 0x5ef1dc9d, "snd_info_create_module_entry" },
	{ 0xfffc0a23, "snd_info_register" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=snd";


MODULE_INFO(srcversion, "FB5336FFC472F1CF54D9DCC");
