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
	{ 0x7406f5c5, "kobject_put" },
	{ 0xff95a544, "kmalloc_caches" },
	{ 0x61528b43, "kobject_get" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0xc897c382, "sg_init_table" },
	{ 0x9b388444, "get_zeroed_page" },
	{ 0xe6fbe430, "can_do_mlock" },
	{ 0x76ebea8, "pv_lock_ops" },
	{ 0x349cba85, "strchr" },
	{ 0x8d848800, "page_address" },
	{ 0x32b558f3, "dev_set_drvdata" },
	{ 0x43a53735, "__alloc_workqueue_key" },
	{ 0xc8b57c27, "autoremove_wake_function" },
	{ 0xfeecde99, "kobject_uevent" },
	{ 0x89b2bb97, "set_page_dirty_lock" },
	{ 0x33543801, "queue_work" },
	{ 0x3fec048f, "sg_next" },
	{ 0xd35e9659, "mutex_unlock" },
	{ 0xbeda57e8, "mmput" },
	{ 0x91715312, "sprintf" },
	{ 0x77e6bb35, "sysfs_remove_group" },
	{ 0x73122ea, "kthread_create_on_node" },
	{ 0xdc5501fb, "skb_trim" },
	{ 0xed52f156, "kobject_create_and_add" },
	{ 0xb2744b36, "down_write_trylock" },
	{ 0x68dfc59f, "__init_waitqueue_head" },
	{ 0xc0004d1d, "netlink_kernel_create" },
	{ 0x2bc95bd4, "memset" },
	{ 0xffdb343b, "device_register" },
	{ 0xf97456ea, "_raw_spin_unlock_irqrestore" },
	{ 0x4c1cb91e, "current_task" },
	{ 0xfc629f82, "__mutex_init" },
	{ 0x50eedeb8, "printk" },
	{ 0x20c55ae0, "sscanf" },
	{ 0x13b1d315, "kthread_stop" },
	{ 0x5aa1d0c9, "sysfs_create_group" },
	{ 0x5152e605, "memcmp" },
	{ 0x483681b6, "class_unregister" },
	{ 0xb4af5836, "get_task_mm" },
	{ 0x69a19375, "kobject_init_and_add" },
	{ 0xcc102fef, "netlink_kernel_release" },
	{ 0x3ce7bbca, "netlink_rcv_skb" },
	{ 0xb4390f9a, "mcount" },
	{ 0x5879b9d9, "nla_put" },
	{ 0x6c2e3320, "strncmp" },
	{ 0x73e20c1c, "strlcpy" },
	{ 0xd36d011b, "mutex_lock" },
	{ 0x8c03d20c, "destroy_workqueue" },
	{ 0xbc1afedf, "up_write" },
	{ 0xb5f636b1, "init_net" },
	{ 0x98ae5de4, "__class_register" },
	{ 0x61b5ade0, "down_write" },
	{ 0x42160169, "flush_workqueue" },
	{ 0xf11543ff, "find_first_zero_bit" },
	{ 0x76fbc6e7, "device_create_file" },
	{ 0xc6cbbc89, "capable" },
	{ 0x8ff4079b, "pv_irq_ops" },
	{ 0x1790d76b, "_raw_read_lock_irqsave" },
	{ 0x93fca811, "__get_free_pages" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x6bda085f, "get_user_pages" },
	{ 0x4292364c, "schedule" },
	{ 0xf1faac3a, "_raw_spin_lock_irq" },
	{ 0x703b4352, "_raw_read_unlock_irqrestore" },
	{ 0x95f89a33, "_raw_write_lock_irq" },
	{ 0xdeb2fcde, "wake_up_process" },
	{ 0x496d7988, "kmem_cache_alloc_trace" },
	{ 0x21fb443e, "_raw_spin_lock_irqsave" },
	{ 0x4302d0eb, "free_pages" },
	{ 0xe45f60d8, "__wake_up" },
	{ 0xd2965f6f, "kthread_should_stop" },
	{ 0x37a0cba, "kfree" },
	{ 0x2e60bace, "memcpy" },
	{ 0x622fa02a, "prepare_to_wait" },
	{ 0xfe04f3f7, "put_page" },
	{ 0x75bb675a, "finish_wait" },
	{ 0x1de9da1d, "device_unregister" },
	{ 0xb81960ca, "snprintf" },
	{ 0xdafbef85, "dev_set_name" },
	{ 0xbd14a0cc, "__nlmsg_put" },
	{ 0x444e490b, "dma_ops" },
	{ 0x5d59a28f, "__netlink_dump_start" },
	{ 0xa7f92105, "add_uevent_var" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "EEA22748F60B0CC23FF1EE2");
