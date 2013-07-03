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
	{ 0x12da5bb2, "__kmalloc" },
	{ 0x24a94b26, "snd_info_get_line" },
	{ 0xa6a732a0, "put_pid" },
	{ 0x72df2f2a, "up_read" },
	{ 0x6e52ce12, "snd_device_register" },
	{ 0xcaf96895, "mem_map" },
	{ 0x76ebea8, "pv_lock_ops" },
	{ 0x3b91f3af, "snd_free_pages" },
	{ 0x15692c87, "param_ops_int" },
	{ 0xea124bd1, "gcd" },
	{ 0x9d892cdf, "snd_register_device_for_dev" },
	{ 0x8c24d342, "snd_card_unref" },
	{ 0x77a18bdd, "snd_card_file_remove" },
	{ 0x7bf21440, "snd_dma_alloc_pages" },
	{ 0x2aa09578, "snd_device_free" },
	{ 0x827d3194, "pid_vnr" },
	{ 0x3a013b7d, "remove_wait_queue" },
	{ 0xd85df7d4, "boot_cpu_data" },
	{ 0x46608fa0, "getnstimeofday" },
	{ 0xc1cf73a6, "snd_power_wait" },
	{ 0xac85d766, "no_llseek" },
	{ 0xc01cf848, "_raw_read_lock" },
	{ 0x942fb0c3, "snd_info_create_card_entry" },
	{ 0xd46e5b30, "pm_qos_add_request" },
	{ 0x4121fd7c, "pm_qos_remove_request" },
	{ 0x20000329, "simple_strtoul" },
	{ 0xb2e5ae4a, "snd_lookup_minor_data" },
	{ 0x6729d3df, "__get_user_4" },
	{ 0xd35e9659, "mutex_unlock" },
	{ 0x999e8297, "vfree" },
	{ 0x91715312, "sprintf" },
	{ 0xdfa741d7, "nonseekable_open" },
	{ 0x7d11c268, "jiffies" },
	{ 0xd0f0d945, "down_read" },
	{ 0xc715f77c, "snd_ctl_unregister_ioctl" },
	{ 0x68dfc59f, "__init_waitqueue_head" },
	{ 0xffd5a395, "default_wake_function" },
	{ 0x7cdcdbe9, "snd_dma_get_reserved_buf" },
	{ 0x2bc95bd4, "memset" },
	{ 0x827e959c, "snd_device_new" },
	{ 0x433944f6, "current_task" },
	{ 0x9be7376a, "snd_timer_new" },
	{ 0xfc629f82, "__mutex_init" },
	{ 0x50eedeb8, "printk" },
	{ 0x5383f34b, "_raw_spin_trylock" },
	{ 0x5152e605, "memcmp" },
	{ 0x8366bded, "snd_unregister_device" },
	{ 0xade88e76, "snd_malloc_pages" },
	{ 0xa1c76e0a, "_cond_resched" },
	{ 0x2f287f0d, "copy_to_user" },
	{ 0xad0faef, "fasync_helper" },
	{ 0xb4390f9a, "mcount" },
	{ 0x73e20c1c, "strlcpy" },
	{ 0xd36d011b, "mutex_lock" },
	{ 0x8f595b11, "snd_major" },
	{ 0xbc1afedf, "up_write" },
	{ 0x61b5ade0, "down_write" },
	{ 0xeb098ed4, "fput" },
	{ 0x60253fea, "__get_page_tail" },
	{ 0x4b015768, "snd_iprintf" },
	{ 0x74a91bd7, "module_put" },
	{ 0x8ff4079b, "pv_irq_ops" },
	{ 0x1790d76b, "_raw_read_lock_irqsave" },
	{ 0xb2fd5ceb, "__put_user_4" },
	{ 0xcd8480f8, "snd_card_file_add" },
	{ 0x8a1987a5, "snd_ctl_register_ioctl" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x3bd1b1f6, "msecs_to_jiffies" },
	{ 0x4292364c, "schedule" },
	{ 0xd62c833f, "schedule_timeout" },
	{ 0xbb7d1550, "pm_qos_request_active" },
	{ 0xe123ca9c, "snd_dma_free_pages" },
	{ 0x703b4352, "_raw_read_unlock_irqrestore" },
	{ 0x95f89a33, "_raw_write_lock_irq" },
	{ 0x8acb2c4e, "kmem_cache_alloc_trace" },
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
	{ 0x4f1ce2f3, "snd_add_device_sysfs_file" },
	{ 0x417351d2, "snd_info_free_entry" },
	{ 0x5084e1db, "snd_timer_interrupt" },
	{ 0x6128b5fc, "__printk_ratelimit" },
	{ 0x6a85a3d, "fget" },
	{ 0x75b3d00e, "kill_fasync" },
	{ 0xc22c941d, "vm_iomap_memory" },
	{ 0x59275138, "snd_timer_notify" },
	{ 0xe2e8065e, "memdup_user" },
	{ 0xb81960ca, "snprintf" },
	{ 0x765de1f6, "vmalloc_to_page" },
	{ 0x362ef408, "_copy_from_user" },
	{ 0xbd7464c5, "snd_info_create_module_entry" },
	{ 0xad7bed17, "dev_get_drvdata" },
	{ 0xe9e7e34c, "snd_info_register" },
	{ 0x9cad4dbd, "try_module_get" },
	{ 0xd35e249a, "_raw_read_lock_irq" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=snd,snd-page-alloc,snd-timer";


MODULE_INFO(srcversion, "AA59FF1F2B361334024D7F2");
