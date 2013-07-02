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
	{ 0x94546d8c, "single_release" },
	{ 0x3f81ddad, "seq_read" },
	{ 0x65a37537, "seq_lseek" },
	{ 0x15692c87, "param_ops_int" },
	{ 0xc9943b6c, "proc_net_remove" },
	{ 0xfe769456, "unregister_netdevice_notifier" },
	{ 0xfe7c4287, "nr_cpu_ids" },
	{ 0xc0a3d105, "find_next_bit" },
	{ 0x3fa58ef8, "wait_for_completion" },
	{ 0x82d258eb, "wake_up_process" },
	{ 0x74fbabae, "kthread_stop" },
	{ 0x35e0cb10, "kthread_bind" },
	{ 0x8b914fa0, "kthread_create_on_node" },
	{ 0x2d37342e, "cpu_online_mask" },
	{ 0x63ecad53, "register_netdevice_notifier" },
	{ 0x9ada1bb8, "proc_mkdir" },
	{ 0x57d7aa89, "dev_get_by_name" },
	{ 0x9e0c711d, "vzalloc_node" },
	{ 0x7807eace, "kmem_cache_alloc_trace" },
	{ 0x440a4045, "kmalloc_caches" },
	{ 0x75bb675a, "finish_wait" },
	{ 0xd62c833f, "schedule_timeout" },
	{ 0x622fa02a, "prepare_to_wait" },
	{ 0x4482cdb, "__refrigerator" },
	{ 0x97d78524, "freezing_slow_path" },
	{ 0xe914e41e, "strcpy" },
	{ 0x7ab88a45, "system_freezing_cnt" },
	{ 0xd2965f6f, "kthread_should_stop" },
	{ 0x9e61bb05, "set_freezable" },
	{ 0x19a9e62b, "complete" },
	{ 0x68dfc59f, "__init_waitqueue_head" },
	{ 0xc8b57c27, "autoremove_wake_function" },
	{ 0x25c677c4, "mac_pton" },
	{ 0xb81960ca, "snprintf" },
	{ 0xb6ed1e53, "strncpy" },
	{ 0x37ff4c06, "copy_from_user_overflow" },
	{ 0xe2d5255a, "strcmp" },
	{ 0xc6cbbc89, "capable" },
	{ 0x860cbb18, "hrtimer_start_range_ns" },
	{ 0xb75d662a, "hrtimer_cancel" },
	{ 0x897482db, "hrtimer_init_sleeper" },
	{ 0xea905975, "hrtimer_init" },
	{ 0x7179af57, "__netdev_alloc_skb" },
	{ 0x7d11c268, "jiffies" },
	{ 0x8bf826c, "_raw_spin_unlock_bh" },
	{ 0xf6ebc03b, "net_ratelimit" },
	{ 0xa4eb4eff, "_raw_spin_lock_bh" },
	{ 0x802d552f, "skb_pull" },
	{ 0xa438553c, "pskb_expand_head" },
	{ 0x4fd0cf10, "skb_push" },
	{ 0xb76ca35f, "__alloc_skb" },
	{ 0x37a0cba, "kfree" },
	{ 0x2d1137b7, "put_page" },
	{ 0x999e8297, "vfree" },
	{ 0xf1deabf2, "div64_u64" },
	{ 0x91715312, "sprintf" },
	{ 0x4cdb3178, "ns_to_timeval" },
	{ 0xd3fa43d6, "kfree_skb" },
	{ 0x4292364c, "schedule" },
	{ 0xce46e140, "ktime_get_ts" },
	{ 0x39a0f94a, "__xfrm_state_destroy" },
	{ 0x50eedeb8, "printk" },
	{ 0x9c55cec, "schedule_timeout_interruptible" },
	{ 0x3bd1b1f6, "msecs_to_jiffies" },
	{ 0xdf420b68, "proc_create_data" },
	{ 0x88ef4b8, "remove_proc_entry" },
	{ 0x2c0a55e2, "__alloc_pages_nodemask" },
	{ 0x8def339e, "contig_page_data" },
	{ 0xf23c2be, "__get_page_tail" },
	{ 0x4f68e5c9, "do_gettimeofday" },
	{ 0x2bc95bd4, "memset" },
	{ 0xd423dea4, "skb_put" },
	{ 0xcaaa73f3, "xfrm_stateonly_find" },
	{ 0x95f3164e, "init_net" },
	{ 0x47c7b0d2, "cpu_number" },
	{ 0xb86e4ab9, "random32" },
	{ 0x96c7e43b, "seq_printf" },
	{ 0x6339a8bc, "mutex_unlock" },
	{ 0xcc5005fe, "msleep_interruptible" },
	{ 0x215f9a25, "current_task" },
	{ 0xcf510c4a, "mutex_lock" },
	{ 0x76ebea8, "pv_lock_ops" },
	{ 0x6c2e3320, "strncmp" },
	{ 0x67f7403e, "_raw_spin_lock" },
	{ 0x11f7ed4c, "hex_to_bin" },
	{ 0x362ef408, "_copy_from_user" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0xd0d8621b, "strlen" },
	{ 0xb742fd7, "simple_strtol" },
	{ 0x1b6314fd, "in_aton" },
	{ 0x20000329, "simple_strtoul" },
	{ 0x167e7f9d, "__get_user_1" },
	{ 0xa1c76e0a, "_cond_resched" },
	{ 0x96a592f6, "seq_puts" },
	{ 0x231f39b0, "single_open" },
	{ 0xb4390f9a, "mcount" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "24071E35CE75A2CF91495F5");
