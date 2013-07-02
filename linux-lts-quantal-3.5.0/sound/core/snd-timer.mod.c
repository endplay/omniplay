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
	{ 0x402b8281, "__request_module" },
	{ 0x440a4045, "kmalloc_caches" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0x76ebea8, "pv_lock_ops" },
	{ 0x15692c87, "param_ops_int" },
	{ 0xc996d097, "del_timer" },
	{ 0xc957f612, "snd_register_device_for_dev" },
	{ 0x3a013b7d, "remove_wait_queue" },
	{ 0x46608fa0, "getnstimeofday" },
	{ 0x1e06b4b3, "no_llseek" },
	{ 0x6729d3df, "__get_user_4" },
	{ 0xeae3dfd6, "__const_udelay" },
	{ 0xfb0e29f, "init_timer_key" },
	{ 0x6339a8bc, "mutex_unlock" },
	{ 0x91715312, "sprintf" },
	{ 0xc499ae1e, "kstrdup" },
	{ 0x2bc2ec5e, "nonseekable_open" },
	{ 0x7d11c268, "jiffies" },
	{ 0x68dfc59f, "__init_waitqueue_head" },
	{ 0xffd5a395, "default_wake_function" },
	{ 0xf58014ed, "snd_device_new" },
	{ 0xf97456ea, "_raw_spin_unlock_irqrestore" },
	{ 0x215f9a25, "current_task" },
	{ 0xc5c74531, "__mutex_init" },
	{ 0x50eedeb8, "printk" },
	{ 0x7a8b40fb, "snd_unregister_device" },
	{ 0x8df3789f, "snd_oss_info_register" },
	{ 0xfaef0ed, "__tasklet_schedule" },
	{ 0xa1c76e0a, "_cond_resched" },
	{ 0x2f287f0d, "copy_to_user" },
	{ 0x58e9f43f, "fasync_helper" },
	{ 0xb4390f9a, "mcount" },
	{ 0x3971b4df, "snd_ecards_limit" },
	{ 0x73e20c1c, "strlcpy" },
	{ 0xcf510c4a, "mutex_lock" },
	{ 0x9545af6d, "tasklet_init" },
	{ 0xbe2c0274, "add_timer" },
	{ 0x4b015768, "snd_iprintf" },
	{ 0xc5f0996, "module_put" },
	{ 0x8ff4079b, "pv_irq_ops" },
	{ 0xb2fd5ceb, "__put_user_4" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x4292364c, "schedule" },
	{ 0xf1faac3a, "_raw_spin_lock_irq" },
	{ 0x7807eace, "kmem_cache_alloc_trace" },
	{ 0x67f7403e, "_raw_spin_lock" },
	{ 0x21fb443e, "_raw_spin_lock_irqsave" },
	{ 0xce46e140, "ktime_get_ts" },
	{ 0xe45f60d8, "__wake_up" },
	{ 0xd7bd3af2, "add_wait_queue" },
	{ 0x37a0cba, "kfree" },
	{ 0x6514d1b3, "snd_info_free_entry" },
	{ 0x1b9a76b1, "kill_fasync" },
	{ 0xe2e8065e, "memdup_user" },
	{ 0x362ef408, "_copy_from_user" },
	{ 0x307bd854, "snd_info_create_module_entry" },
	{ 0x7b545f03, "snd_info_register" },
	{ 0x20ae0365, "try_module_get" },
	{ 0xe914e41e, "strcpy" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=snd";


MODULE_INFO(srcversion, "B27B6D394B8D52A14F91487");
