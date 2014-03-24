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
	{ 0xb0c0a67a, "single_release" },
	{ 0xa4d730ea, "seq_read" },
	{ 0xe4733450, "seq_lseek" },
	{ 0x15692c87, "param_ops_int" },
	{ 0xf719d263, "proc_net_remove" },
	{ 0xfe769456, "unregister_netdevice_notifier" },
	{ 0xfe7c4287, "nr_cpu_ids" },
	{ 0xc0a3d105, "find_next_bit" },
	{ 0x3fa58ef8, "wait_for_completion" },
	{ 0xdeb2fcde, "wake_up_process" },
	{ 0x13b1d315, "kthread_stop" },
	{ 0x16cbb527, "kthread_bind" },
	{ 0x73122ea, "kthread_create_on_node" },
	{ 0x2d37342e, "cpu_online_mask" },
	{ 0x63ecad53, "register_netdevice_notifier" },
	{ 0xfa9d9a8f, "proc_mkdir" },
	{ 0xae71b296, "dev_get_by_name" },
	{ 0x9e0c711d, "vzalloc_node" },
	{ 0x496d7988, "kmem_cache_alloc_trace" },
	{ 0xff95a544, "kmalloc_caches" },
	{ 0x75bb675a, "finish_wait" },
	{ 0xd62c833f, "schedule_timeout" },
	{ 0x622fa02a, "prepare_to_wait" },
	{ 0x4482cdb, "__refrigerator" },
	{ 0xddb1811d, "freezing_slow_path" },
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
	{ 0xc8ba836b, "hrtimer_init_sleeper" },
	{ 0xea905975, "hrtimer_init" },
	{ 0x31ee8f1d, "__netdev_alloc_skb" },
	{ 0x7d11c268, "jiffies" },
	{ 0x8bf826c, "_raw_spin_unlock_bh" },
	{ 0xf6ebc03b, "net_ratelimit" },
	{ 0xa4eb4eff, "_raw_spin_lock_bh" },
	{ 0x40b510c8, "skb_pull" },
	{ 0xca8c5107, "pskb_expand_head" },
	{ 0x21183263, "skb_push" },
	{ 0x8e21f373, "__alloc_skb" },
	{ 0x37a0cba, "kfree" },
	{ 0xfe04f3f7, "put_page" },
	{ 0x999e8297, "vfree" },
	{ 0xf1deabf2, "div64_u64" },
	{ 0x91715312, "sprintf" },
	{ 0x4cdb3178, "ns_to_timeval" },
	{ 0x314cc2de, "kfree_skb" },
	{ 0x4292364c, "schedule" },
	{ 0xce46e140, "ktime_get_ts" },
	{ 0x50d16975, "__xfrm_state_destroy" },
	{ 0x50eedeb8, "printk" },
	{ 0x9c55cec, "schedule_timeout_interruptible" },
	{ 0x3bd1b1f6, "msecs_to_jiffies" },
	{ 0xbcafc78f, "proc_create_data" },
	{ 0x3ad70291, "remove_proc_entry" },
	{ 0x45ad1a1f, "__alloc_pages_nodemask" },
	{ 0x8def339e, "contig_page_data" },
	{ 0x1cfcb04d, "__get_page_tail" },
	{ 0x4f68e5c9, "do_gettimeofday" },
	{ 0x2bc95bd4, "memset" },
	{ 0x76515662, "skb_put" },
	{ 0xd980b65c, "xfrm_stateonly_find" },
	{ 0xb5f636b1, "init_net" },
	{ 0x47c7b0d2, "cpu_number" },
	{ 0xb86e4ab9, "random32" },
	{ 0x96c7e43b, "seq_printf" },
	{ 0xd35e9659, "mutex_unlock" },
	{ 0xcc5005fe, "msleep_interruptible" },
	{ 0x4c1cb91e, "current_task" },
	{ 0xd36d011b, "mutex_lock" },
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
	{ 0xc0e82f2d, "single_open" },
	{ 0xb4390f9a, "mcount" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "24071E35CE75A2CF91495F5");
