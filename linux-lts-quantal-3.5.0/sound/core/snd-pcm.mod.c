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
	{ 0x24a94b26, "snd_info_get_line" },
	{ 0x964b7920, "put_pid" },
	{ 0x72df2f2a, "up_read" },
	{ 0x72e2cee, "snd_device_register" },
	{ 0xfc9c80e4, "mem_map" },
	{ 0x76ebea8, "pv_lock_ops" },
	{ 0x3b91f3af, "snd_free_pages" },
	{ 0x15692c87, "param_ops_int" },
	{ 0xea124bd1, "gcd" },
	{ 0xc957f612, "snd_register_device_for_dev" },
	{ 0x4bda239c, "snd_card_unref" },
	{ 0x72c3cad, "snd_card_file_remove" },
	{ 0x7bf21440, "snd_dma_alloc_pages" },
	{ 0x1b9b2620, "snd_device_free" },
	{ 0x4e0ee1d1, "pid_vnr" },
	{ 0x3a013b7d, "remove_wait_queue" },
	{ 0xd85df7d4, "boot_cpu_data" },
	{ 0x46608fa0, "getnstimeofday" },
	{ 0x8f0985c3, "snd_power_wait" },
	{ 0x1e06b4b3, "no_llseek" },
	{ 0xc01cf848, "_raw_read_lock" },
	{ 0x19200c52, "snd_info_create_card_entry" },
	{ 0xd46e5b30, "pm_qos_add_request" },
	{ 0x4121fd7c, "pm_qos_remove_request" },
	{ 0x20000329, "simple_strtoul" },
	{ 0xb2e5ae4a, "snd_lookup_minor_data" },
	{ 0x6729d3df, "__get_user_4" },
	{ 0x6339a8bc, "mutex_unlock" },
	{ 0x999e8297, "vfree" },
	{ 0x91715312, "sprintf" },
	{ 0x2bc2ec5e, "nonseekable_open" },
	{ 0x7d11c268, "jiffies" },
	{ 0xd0f0d945, "down_read" },
	{ 0xf3298027, "snd_ctl_unregister_ioctl" },
	{ 0x68dfc59f, "__init_waitqueue_head" },
	{ 0xffd5a395, "default_wake_function" },
	{ 0x7cdcdbe9, "snd_dma_get_reserved_buf" },
	{ 0x2bc95bd4, "memset" },
	{ 0xf58014ed, "snd_device_new" },
	{ 0x215f9a25, "current_task" },
	{ 0x51c07926, "snd_timer_new" },
	{ 0xc5c74531, "__mutex_init" },
	{ 0x50eedeb8, "printk" },
	{ 0x5383f34b, "_raw_spin_trylock" },
	{ 0x5152e605, "memcmp" },
	{ 0x7a8b40fb, "snd_unregister_device" },
	{ 0xade88e76, "snd_malloc_pages" },
	{ 0xa1c76e0a, "_cond_resched" },
	{ 0x2f287f0d, "copy_to_user" },
	{ 0x58e9f43f, "fasync_helper" },
	{ 0xb4390f9a, "mcount" },
	{ 0x73e20c1c, "strlcpy" },
	{ 0xcf510c4a, "mutex_lock" },
	{ 0x8f595b11, "snd_major" },
	{ 0xbc1afedf, "up_write" },
	{ 0x61b5ade0, "down_write" },
	{ 0xfde963c0, "fput" },
	{ 0xf23c2be, "__get_page_tail" },
	{ 0x4b015768, "snd_iprintf" },
	{ 0xc5f0996, "module_put" },
	{ 0x8ff4079b, "pv_irq_ops" },
	{ 0x1790d76b, "_raw_read_lock_irqsave" },
	{ 0xb2fd5ceb, "__put_user_4" },
	{ 0x26a5823, "snd_card_file_add" },
	{ 0xfd7e771f, "snd_ctl_register_ioctl" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x3bd1b1f6, "msecs_to_jiffies" },
	{ 0x4292364c, "schedule" },
	{ 0xd62c833f, "schedule_timeout" },
	{ 0xbb7d1550, "pm_qos_request_active" },
	{ 0xe123ca9c, "snd_dma_free_pages" },
	{ 0x703b4352, "_raw_read_unlock_irqrestore" },
	{ 0x95f89a33, "_raw_write_lock_irq" },
	{ 0x7807eace, "kmem_cache_alloc_trace" },
	{ 0xe647875e, "snd_dma_reserve_buf" },
	{ 0x67f7403e, "_raw_spin_lock" },
	{ 0xce46e140, "ktime_get_ts" },
	{ 0xe45f60d8, "__wake_up" },
	{ 0xd7bd3af2, "add_wait_queue" },
	{ 0x9e6d79f8, "snd_info_get_str" },
	{ 0x5705088a, "__vmalloc" },
	{ 0x9c55cec, "schedule_timeout_interruptible" },
	{ 0x37a0cba, "kfree" },
	{ 0x2e60bace, "memcpy" },
	{ 0x4a970111, "snd_add_device_sysfs_file" },
	{ 0x6514d1b3, "snd_info_free_entry" },
	{ 0x8f69ad65, "snd_timer_interrupt" },
	{ 0x6128b5fc, "__printk_ratelimit" },
	{ 0x3bb2d799, "fget" },
	{ 0x1b9a76b1, "kill_fasync" },
	{ 0x25e7f355, "vm_iomap_memory" },
	{ 0x8ba10f, "snd_timer_notify" },
	{ 0xe2e8065e, "memdup_user" },
	{ 0xb81960ca, "snprintf" },
	{ 0xd2705fe1, "vmalloc_to_page" },
	{ 0x362ef408, "_copy_from_user" },
	{ 0x307bd854, "snd_info_create_module_entry" },
	{ 0x42da990e, "dev_get_drvdata" },
	{ 0x7b545f03, "snd_info_register" },
	{ 0x20ae0365, "try_module_get" },
	{ 0xd35e249a, "_raw_read_lock_irq" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=snd,snd-page-alloc,snd-timer";


MODULE_INFO(srcversion, "AA59FF1F2B361334024D7F2");
