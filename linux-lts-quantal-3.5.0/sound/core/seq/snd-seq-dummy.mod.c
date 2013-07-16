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
	{ 0xab5c8523, "module_layout" },
	{ 0x57f98c4b, "kmalloc_caches" },
	{ 0x15692c87, "param_ops_int" },
	{ 0x1a724fcc, "snd_seq_kernel_client_ctl" },
	{ 0x1976aa06, "param_ops_bool" },
	{ 0x8c57686a, "snd_seq_create_kernel_client" },
	{ 0x91715312, "sprintf" },
	{ 0x50eedeb8, "printk" },
	{ 0xb4390f9a, "mcount" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x8acb2c4e, "kmem_cache_alloc_trace" },
	{ 0x3a57f235, "snd_seq_autoload_unlock" },
	{ 0x37a0cba, "kfree" },
	{ 0x3fb4d161, "snd_seq_kernel_client_dispatch" },
	{ 0xb90668b2, "snd_seq_autoload_lock" },
	{ 0x6bb71038, "snd_seq_delete_kernel_client" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=snd-seq,snd-seq-device";


MODULE_INFO(srcversion, "2580130FF0AB4E8B232001A");
