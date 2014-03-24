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
	{ 0x72df2f2a, "up_read" },
	{ 0x50d8c56c, "ib_attach_mcast" },
	{ 0x76ebea8, "pv_lock_ops" },
	{ 0xdbf506b8, "ib_dealloc_pd" },
	{ 0x32b558f3, "dev_set_drvdata" },
	{ 0xd8e484f0, "register_chrdev_region" },
	{ 0xd49af890, "rdma_port_get_link_layer" },
	{ 0xc8b57c27, "autoremove_wake_function" },
	{ 0x440a8c1, "ib_open_qp" },
	{ 0x3bfbd926, "no_llseek" },
	{ 0xc69d007a, "ib_destroy_qp" },
	{ 0xb0f0d236, "device_destroy" },
	{ 0x72b0a36c, "kobject_set_name" },
	{ 0xf559be16, "ib_dealloc_xrcd" },
	{ 0xd35e9659, "mutex_unlock" },
	{ 0x7485e15e, "unregister_chrdev_region" },
	{ 0x60efae6d, "igrab" },
	{ 0x91715312, "sprintf" },
	{ 0x4c1da3de, "nonseekable_open" },
	{ 0x33e3f5e0, "ib_destroy_ah" },
	{ 0x49b5e902, "ib_modify_qp" },
	{ 0xd0f0d945, "down_read" },
	{ 0x733c3b54, "kasprintf" },
	{ 0x68dfc59f, "__init_waitqueue_head" },
	{ 0xa6d972a3, "ib_create_qp" },
	{ 0x3fa58ef8, "wait_for_completion" },
	{ 0x61536865, "idr_destroy" },
	{ 0xf97456ea, "_raw_spin_unlock_irqrestore" },
	{ 0x4c1cb91e, "current_task" },
	{ 0x99bfbe39, "get_unused_fd" },
	{ 0xddea3160, "ib_query_device" },
	{ 0xfc629f82, "__mutex_init" },
	{ 0x50eedeb8, "printk" },
	{ 0x5152e605, "memcmp" },
	{ 0xc7e06385, "ib_destroy_srq" },
	{ 0xedb144e1, "ib_get_client_data" },
	{ 0xc0580937, "rb_erase" },
	{ 0x2f287f0d, "copy_to_user" },
	{ 0x1c7e0d4d, "fasync_helper" },
	{ 0xb4390f9a, "mcount" },
	{ 0xa05e93f9, "ib_query_port" },
	{ 0x16305289, "warn_slowpath_null" },
	{ 0xd36d011b, "mutex_lock" },
	{ 0x4f220c3f, "device_create" },
	{ 0x63f0f758, "class_create_file" },
	{ 0xbc1afedf, "up_write" },
	{ 0x61b5ade0, "down_write" },
	{ 0xb91507bc, "ib_set_client_data" },
	{ 0x58404e4d, "fput" },
	{ 0x7042e52f, "ib_destroy_cq" },
	{ 0xf11543ff, "find_first_zero_bit" },
	{ 0xb6588e7a, "idr_remove" },
	{ 0x76fbc6e7, "device_create_file" },
	{ 0xa53e61e5, "cdev_add" },
	{ 0x419ee6e8, "idr_pre_get" },
	{ 0xa1534f27, "ib_register_client" },
	{ 0x4213f57b, "module_put" },
	{ 0xd8efd162, "ib_create_ah" },
	{ 0xc6cbbc89, "capable" },
	{ 0xb572363f, "ib_unregister_event_handler" },
	{ 0x8ff4079b, "pv_irq_ops" },
	{ 0x97c13ae8, "ib_detach_mcast" },
	{ 0x5c4af8cf, "ib_register_event_handler" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x4292364c, "schedule" },
	{ 0xf1faac3a, "_raw_spin_lock_irq" },
	{ 0x3f4547a7, "put_unused_fd" },
	{ 0x496d7988, "kmem_cache_alloc_trace" },
	{ 0x67f7403e, "_raw_spin_lock" },
	{ 0x21fb443e, "_raw_spin_lock_irqsave" },
	{ 0xa6dcc773, "rb_insert_color" },
	{ 0xfff75497, "ib_query_qp" },
	{ 0xd2d909c4, "ib_dereg_mr" },
	{ 0xe45f60d8, "__wake_up" },
	{ 0x3fda860d, "iput" },
	{ 0x37a0cba, "kfree" },
	{ 0x7422c45a, "fd_install" },
	{ 0x622fa02a, "prepare_to_wait" },
	{ 0xdc1e083, "ib_query_srq" },
	{ 0xa0c3e167, "fget" },
	{ 0xbf56d1ec, "class_destroy" },
	{ 0x1c02b222, "kill_fasync" },
	{ 0x75bb675a, "finish_wait" },
	{ 0x19a9e62b, "complete" },
	{ 0xb4e8d6ab, "ib_close_qp" },
	{ 0x362ef408, "_copy_from_user" },
	{ 0xf12a5c83, "idr_find" },
	{ 0xcf030c65, "__class_create" },
	{ 0x92a05f3d, "idr_get_new" },
	{ 0xad7bed17, "dev_get_drvdata" },
	{ 0xe62c731b, "show_class_attr_string" },
	{ 0x19aef1a3, "ib_unregister_client" },
	{ 0x657879ce, "__init_rwsem" },
	{ 0xefad3e5a, "anon_inode_getfile" },
	{ 0x29537c9e, "alloc_chrdev_region" },
	{ 0xa49a6eba, "try_module_get" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=ib_core";


MODULE_INFO(srcversion, "A7DA29BF1373AE8A19213B1");
