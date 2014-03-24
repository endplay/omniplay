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
	{ 0x24a94b26, "snd_info_get_line" },
	{ 0x2ac6bc85, "put_pid" },
	{ 0x72df2f2a, "up_read" },
	{ 0x6e52ce12, "snd_device_register" },
	{ 0xec43ff28, "mem_map" },
	{ 0x76ebea8, "pv_lock_ops" },
	{ 0x3b91f3af, "snd_free_pages" },
	{ 0x15692c87, "param_ops_int" },
	{ 0xea124bd1, "gcd" },
	{ 0xb41d3ae6, "snd_register_device_for_dev" },
	{ 0xcd680a86, "snd_card_unref" },
	{ 0x48f77908, "snd_card_file_remove" },
	{ 0x7f544d33, "snd_dma_alloc_pages" },
	{ 0x2aa09578, "snd_device_free" },
	{ 0xdb95a99, "pid_vnr" },
	{ 0x3a013b7d, "remove_wait_queue" },
	{ 0xd85df7d4, "boot_cpu_data" },
	{ 0x46608fa0, "getnstimeofday" },
	{ 0x250c3385, "snd_power_wait" },
	{ 0x3bfbd926, "no_llseek" },
	{ 0xc01cf848, "_raw_read_lock" },
	{ 0x77aa089b, "snd_info_create_card_entry" },
	{ 0xd46e5b30, "pm_qos_add_request" },
	{ 0x4121fd7c, "pm_qos_remove_request" },
	{ 0x20000329, "simple_strtoul" },
	{ 0xb2e5ae4a, "snd_lookup_minor_data" },
	{ 0x6729d3df, "__get_user_4" },
	{ 0xd35e9659, "mutex_unlock" },
	{ 0x999e8297, "vfree" },
	{ 0x91715312, "sprintf" },
	{ 0x4c1da3de, "nonseekable_open" },
	{ 0x7d11c268, "jiffies" },
	{ 0xd0f0d945, "down_read" },
	{ 0x75963f26, "snd_ctl_unregister_ioctl" },
	{ 0x68dfc59f, "__init_waitqueue_head" },
	{ 0xffd5a395, "default_wake_function" },
	{ 0x76a1ba27, "snd_dma_get_reserved_buf" },
	{ 0x2bc95bd4, "memset" },
	{ 0x827e959c, "snd_device_new" },
	{ 0x4c1cb91e, "current_task" },
	{ 0xefcbeb64, "snd_timer_new" },
	{ 0xfc629f82, "__mutex_init" },
	{ 0x50eedeb8, "printk" },
	{ 0x5383f34b, "_raw_spin_trylock" },
	{ 0x5152e605, "memcmp" },
	{ 0x9c5d9389, "snd_unregister_device" },
	{ 0xade88e76, "snd_malloc_pages" },
	{ 0xa1c76e0a, "_cond_resched" },
	{ 0x2f287f0d, "copy_to_user" },
	{ 0x1c7e0d4d, "fasync_helper" },
	{ 0xb4390f9a, "mcount" },
	{ 0x73e20c1c, "strlcpy" },
	{ 0xd36d011b, "mutex_lock" },
	{ 0x8f595b11, "snd_major" },
	{ 0xbc1afedf, "up_write" },
	{ 0x61b5ade0, "down_write" },
	{ 0x58404e4d, "fput" },
	{ 0x1cfcb04d, "__get_page_tail" },
	{ 0x4b015768, "snd_iprintf" },
	{ 0x4213f57b, "module_put" },
	{ 0x8ff4079b, "pv_irq_ops" },
	{ 0x1790d76b, "_raw_read_lock_irqsave" },
	{ 0xb2fd5ceb, "__put_user_4" },
	{ 0xe094f16d, "snd_card_file_add" },
	{ 0x8dac01aa, "snd_ctl_register_ioctl" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x3bd1b1f6, "msecs_to_jiffies" },
	{ 0x4292364c, "schedule" },
	{ 0xd62c833f, "schedule_timeout" },
	{ 0xbb7d1550, "pm_qos_request_active" },
	{ 0x3272c0d, "snd_dma_free_pages" },
	{ 0x703b4352, "_raw_read_unlock_irqrestore" },
	{ 0x95f89a33, "_raw_write_lock_irq" },
	{ 0x496d7988, "kmem_cache_alloc_trace" },
	{ 0xb2a4bc36, "snd_dma_reserve_buf" },
	{ 0x67f7403e, "_raw_spin_lock" },
	{ 0xce46e140, "ktime_get_ts" },
	{ 0xe45f60d8, "__wake_up" },
	{ 0xd7bd3af2, "add_wait_queue" },
	{ 0x9e6d79f8, "snd_info_get_str" },
	{ 0x5705088a, "__vmalloc" },
	{ 0x9c55cec, "schedule_timeout_interruptible" },
	{ 0x37a0cba, "kfree" },
	{ 0x2e60bace, "memcpy" },
	{ 0xd192e8e8, "snd_add_device_sysfs_file" },
	{ 0xeaf57edb, "snd_info_free_entry" },
	{ 0xb681653d, "snd_timer_interrupt" },
	{ 0x6128b5fc, "__printk_ratelimit" },
	{ 0xa0c3e167, "fget" },
	{ 0x1c02b222, "kill_fasync" },
	{ 0x53659481, "vm_iomap_memory" },
	{ 0x649b4b77, "snd_timer_notify" },
	{ 0xe2e8065e, "memdup_user" },
	{ 0xb81960ca, "snprintf" },
	{ 0x95f5135a, "vmalloc_to_page" },
	{ 0x362ef408, "_copy_from_user" },
	{ 0x5ef1dc9d, "snd_info_create_module_entry" },
	{ 0xad7bed17, "dev_get_drvdata" },
	{ 0xfffc0a23, "snd_info_register" },
	{ 0xa49a6eba, "try_module_get" },
	{ 0xd35e249a, "_raw_read_lock_irq" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=snd,snd-page-alloc,snd-timer";


MODULE_INFO(srcversion, "AA59FF1F2B361334024D7F2");
