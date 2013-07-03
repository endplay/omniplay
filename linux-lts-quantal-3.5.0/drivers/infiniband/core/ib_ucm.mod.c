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
	{ 0xa95e70ac, "cdev_del" },
	{ 0x57f98c4b, "kmalloc_caches" },
	{ 0x238dee61, "ib_send_cm_rej" },
	{ 0x8a62977f, "cdev_init" },
	{ 0xd8e484f0, "register_chrdev_region" },
	{ 0xc8b57c27, "autoremove_wake_function" },
	{ 0x83e32a0d, "ib_send_cm_req" },
	{ 0x53996c56, "ib_send_cm_dreq" },
	{ 0x689a41d9, "ib_send_cm_rtu" },
	{ 0xac85d766, "no_llseek" },
	{ 0x72b0a36c, "kobject_set_name" },
	{ 0xe2fae716, "kmemdup" },
	{ 0x18382f6a, "ib_copy_path_rec_to_user" },
	{ 0x2f847bc, "ib_copy_path_rec_from_user" },
	{ 0xd35e9659, "mutex_unlock" },
	{ 0x7485e15e, "unregister_chrdev_region" },
	{ 0x91715312, "sprintf" },
	{ 0xdfa741d7, "nonseekable_open" },
	{ 0x20550f1c, "ib_send_cm_mra" },
	{ 0x68dfc59f, "__init_waitqueue_head" },
	{ 0x3fa58ef8, "wait_for_completion" },
	{ 0xb4b3d2ba, "ib_send_cm_drep" },
	{ 0x670c3696, "ib_cm_init_qp_attr" },
	{ 0x61536865, "idr_destroy" },
	{ 0xfbdbedb9, "device_register" },
	{ 0x433944f6, "current_task" },
	{ 0xfc629f82, "__mutex_init" },
	{ 0x50eedeb8, "printk" },
	{ 0xedb144e1, "ib_get_client_data" },
	{ 0x2f287f0d, "copy_to_user" },
	{ 0x184f3575, "ib_copy_qp_attr_to_user" },
	{ 0xb4390f9a, "mcount" },
	{ 0x8caeacf7, "ib_send_cm_rep" },
	{ 0xd36d011b, "mutex_lock" },
	{ 0xf5716d1f, "class_remove_file" },
	{ 0xf5fbb7f9, "class_create_file" },
	{ 0xb91507bc, "ib_set_client_data" },
	{ 0x5450105a, "ib_create_cm_id" },
	{ 0xf11543ff, "find_first_zero_bit" },
	{ 0xb6588e7a, "idr_remove" },
	{ 0x835950c, "device_create_file" },
	{ 0x8c1d8d50, "cdev_add" },
	{ 0x419ee6e8, "idr_pre_get" },
	{ 0xa1534f27, "ib_register_client" },
	{ 0x6c9f50d2, "ib_cm_notify" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x4292364c, "schedule" },
	{ 0x96ce6c46, "rdma_node_get_transport" },
	{ 0x8acb2c4e, "kmem_cache_alloc_trace" },
	{ 0xb102d34f, "ib_destroy_cm_id" },
	{ 0x399bd5bc, "ib_send_cm_apr" },
	{ 0xe45f60d8, "__wake_up" },
	{ 0xca5bf5e9, "ib_cm_listen" },
	{ 0x37a0cba, "kfree" },
	{ 0x622fa02a, "prepare_to_wait" },
	{ 0x75bb675a, "finish_wait" },
	{ 0x27f9e856, "device_unregister" },
	{ 0xe2e8065e, "memdup_user" },
	{ 0x19a9e62b, "complete" },
	{ 0x510e8cdd, "ib_send_cm_lap" },
	{ 0x886addea, "cm_class" },
	{ 0xbdef8749, "dev_set_name" },
	{ 0x362ef408, "_copy_from_user" },
	{ 0xf12a5c83, "idr_find" },
	{ 0x92a05f3d, "idr_get_new" },
	{ 0xcf0cce9b, "ib_send_cm_sidr_rep" },
	{ 0x3101ae1b, "show_class_attr_string" },
	{ 0x19aef1a3, "ib_unregister_client" },
	{ 0x29537c9e, "alloc_chrdev_region" },
	{ 0x3d4621cc, "ib_send_cm_sidr_req" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=ib_cm,ib_uverbs,ib_core";


MODULE_INFO(srcversion, "C4880923D6C9371E0E83D2E");
