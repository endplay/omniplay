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
	{ 0x402b8281, "__request_module" },
	{ 0x57f98c4b, "kmalloc_caches" },
	{ 0x72df2f2a, "up_read" },
	{ 0xd6ee688f, "vmalloc" },
	{ 0x76ebea8, "pv_lock_ops" },
	{ 0x15692c87, "param_ops_int" },
	{ 0xd0ee38b8, "schedule_timeout_uninterruptible" },
	{ 0x86d5255f, "_raw_write_lock_irqsave" },
	{ 0x9d892cdf, "snd_register_device_for_dev" },
	{ 0x3a013b7d, "remove_wait_queue" },
	{ 0xac85d766, "no_llseek" },
	{ 0xc01cf848, "_raw_read_lock" },
	{ 0x6339b6d0, "snd_seq_device_load_drivers" },
	{ 0xd35e9659, "mutex_unlock" },
	{ 0x999e8297, "vfree" },
	{ 0x91715312, "sprintf" },
	{ 0xdfa741d7, "nonseekable_open" },
	{ 0xd0f0d945, "down_read" },
	{ 0x168f1082, "_raw_write_unlock_irqrestore" },
	{ 0x68dfc59f, "__init_waitqueue_head" },
	{ 0xffd5a395, "default_wake_function" },
	{ 0xf97456ea, "_raw_spin_unlock_irqrestore" },
	{ 0x433944f6, "current_task" },
	{ 0xf04ba383, "mutex_lock_interruptible" },
	{ 0xfc629f82, "__mutex_init" },
	{ 0x50eedeb8, "printk" },
	{ 0x8366bded, "snd_unregister_device" },
	{ 0xa1c76e0a, "_cond_resched" },
	{ 0x2f287f0d, "copy_to_user" },
	{ 0xb4390f9a, "mcount" },
	{ 0x3971b4df, "snd_ecards_limit" },
	{ 0x6c2e3320, "strncmp" },
	{ 0x73e20c1c, "strlcpy" },
	{ 0xc7f423dc, "snd_timer_pause" },
	{ 0xd36d011b, "mutex_lock" },
	{ 0x517ed0a3, "snd_timer_resolution" },
	{ 0xbc1afedf, "up_write" },
	{ 0x61b5ade0, "down_write" },
	{ 0x4b015768, "snd_iprintf" },
	{ 0x74a91bd7, "module_put" },
	{ 0x739c40ed, "snd_timer_start" },
	{ 0x8ff4079b, "pv_irq_ops" },
	{ 0xb2fd5ceb, "__put_user_4" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x4292364c, "schedule" },
	{ 0x812375bc, "snd_timer_open" },
	{ 0xf1faac3a, "_raw_spin_lock_irq" },
	{ 0x8acb2c4e, "kmem_cache_alloc_trace" },
	{ 0x67f7403e, "_raw_spin_lock" },
	{ 0x3a57f235, "snd_seq_autoload_unlock" },
	{ 0x21fb443e, "_raw_spin_lock_irqsave" },
	{ 0x7afa89fc, "vsnprintf" },
	{ 0xe45f60d8, "__wake_up" },
	{ 0x4f68e5c9, "do_gettimeofday" },
	{ 0xd7bd3af2, "add_wait_queue" },
	{ 0x37a0cba, "kfree" },
	{ 0x2e60bace, "memcpy" },
	{ 0x3c1ded9e, "snd_timer_close" },
	{ 0x584ac26f, "snd_seq_root" },
	{ 0x417351d2, "snd_info_free_entry" },
	{ 0x4845c423, "param_array_ops" },
	{ 0xb90668b2, "snd_seq_autoload_lock" },
	{ 0x4a3ea5c0, "snd_request_card" },
	{ 0xb81960ca, "snprintf" },
	{ 0x362ef408, "_copy_from_user" },
	{ 0xbd7464c5, "snd_info_create_module_entry" },
	{ 0xe9e7e34c, "snd_info_register" },
	{ 0x657879ce, "__init_rwsem" },
	{ 0x9cad4dbd, "try_module_get" },
	{ 0xd997a3aa, "snd_timer_stop" },
	{ 0xe914e41e, "strcpy" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=snd,snd-seq-device,snd-timer";


MODULE_INFO(srcversion, "0C5B1D618C4B04757C0DAF0");
