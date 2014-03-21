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
	{ 0xf94f35e8, "cdev_del" },
	{ 0xff95a544, "kmalloc_caches" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0xbfeacd61, "cdev_init" },
	{ 0x76ebea8, "pv_lock_ops" },
	{ 0x32b558f3, "dev_set_drvdata" },
	{ 0xd8e484f0, "register_chrdev_region" },
	{ 0xc8b57c27, "autoremove_wake_function" },
	{ 0x2fab0a87, "ib_register_mad_agent" },
	{ 0x6bbe84e5, "ib_free_recv_mad" },
	{ 0x3bfbd926, "no_llseek" },
	{ 0x4792c572, "down_interruptible" },
	{ 0xb0f0d236, "device_destroy" },
	{ 0x72b0a36c, "kobject_set_name" },
	{ 0x6729d3df, "__get_user_4" },
	{ 0xd35e9659, "mutex_unlock" },
	{ 0x7485e15e, "unregister_chrdev_region" },
	{ 0x91715312, "sprintf" },
	{ 0x4c1da3de, "nonseekable_open" },
	{ 0x6e351283, "ib_get_rmpp_segment" },
	{ 0x33e3f5e0, "ib_destroy_ah" },
	{ 0x733c3b54, "kasprintf" },
	{ 0xb8aad78a, "ib_free_send_mad" },
	{ 0x7b5d4b7a, "ib_is_mad_class_rmpp" },
	{ 0x68dfc59f, "__init_waitqueue_head" },
	{ 0x4c1cb91e, "current_task" },
	{ 0x44f1606d, "down_trylock" },
	{ 0xfc629f82, "__mutex_init" },
	{ 0x50eedeb8, "printk" },
	{ 0x5152e605, "memcmp" },
	{ 0xedb144e1, "ib_get_client_data" },
	{ 0xa1c76e0a, "_cond_resched" },
	{ 0x2f287f0d, "copy_to_user" },
	{ 0xb4390f9a, "mcount" },
	{ 0x16305289, "warn_slowpath_null" },
	{ 0xd36d011b, "mutex_lock" },
	{ 0x4f220c3f, "device_create" },
	{ 0x40f402b6, "ib_init_ah_from_wc" },
	{ 0x63f0f758, "class_create_file" },
	{ 0xb91507bc, "ib_set_client_data" },
	{ 0x37e98ffb, "ib_create_send_mad" },
	{ 0xf11543ff, "find_first_zero_bit" },
	{ 0x506e9f7f, "ib_post_send_mad" },
	{ 0x946d5d27, "ib_response_mad" },
	{ 0x76fbc6e7, "device_create_file" },
	{ 0xa53e61e5, "cdev_add" },
	{ 0x8b31cefe, "ib_unregister_mad_agent" },
	{ 0xa1534f27, "ib_register_client" },
	{ 0xd8efd162, "ib_create_ah" },
	{ 0x8ff4079b, "pv_irq_ops" },
	{ 0xb2fd5ceb, "__put_user_4" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x4292364c, "schedule" },
	{ 0xf1faac3a, "_raw_spin_lock_irq" },
	{ 0x96ce6c46, "rdma_node_get_transport" },
	{ 0x496d7988, "kmem_cache_alloc_trace" },
	{ 0x67f7403e, "_raw_spin_lock" },
	{ 0xe45f60d8, "__wake_up" },
	{ 0xdccda88b, "ib_modify_port" },
	{ 0x37a0cba, "kfree" },
	{ 0x622fa02a, "prepare_to_wait" },
	{ 0xc4554217, "up" },
	{ 0xbf56d1ec, "class_destroy" },
	{ 0x75bb675a, "finish_wait" },
	{ 0x362ef408, "_copy_from_user" },
	{ 0xcf030c65, "__class_create" },
	{ 0xad7bed17, "dev_get_drvdata" },
	{ 0x6f077fcf, "ib_get_mad_data_offset" },
	{ 0xe62c731b, "show_class_attr_string" },
	{ 0x19aef1a3, "ib_unregister_client" },
	{ 0x29537c9e, "alloc_chrdev_region" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=ib_mad,ib_core";


MODULE_INFO(srcversion, "2FC6A102037737FE4517791");
