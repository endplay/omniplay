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
	{ 0x9116842f, "device_remove_file" },
	{ 0x57f98c4b, "kmalloc_caches" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0xd49af890, "rdma_port_get_link_layer" },
	{ 0xc8b57c27, "autoremove_wake_function" },
	{ 0x1bbd418e, "unregister_net_sysctl_table" },
	{ 0xad5ed6fc, "vlan_dev_vlan_id" },
	{ 0x78db38d3, "proc_dointvec" },
	{ 0xac85d766, "no_llseek" },
	{ 0x11483357, "rdma_join_multicast" },
	{ 0x6393511e, "rdma_accept" },
	{ 0x18382f6a, "ib_copy_path_rec_to_user" },
	{ 0x97767065, "rdma_destroy_id" },
	{ 0xd35e9659, "mutex_unlock" },
	{ 0x7cf5a51, "ib_copy_ah_attr_to_user" },
	{ 0xfa6fa5d8, "rdma_init_qp_attr" },
	{ 0x91715312, "sprintf" },
	{ 0xdfa741d7, "nonseekable_open" },
	{ 0x8dca16c3, "rdma_connect" },
	{ 0xe4d5ed, "rdma_set_reuseaddr" },
	{ 0x68dfc59f, "__init_waitqueue_head" },
	{ 0x3fa58ef8, "wait_for_completion" },
	{ 0x31e0d0f0, "misc_register" },
	{ 0x61536865, "idr_destroy" },
	{ 0x433944f6, "current_task" },
	{ 0xfc629f82, "__mutex_init" },
	{ 0x50eedeb8, "printk" },
	{ 0xc04c1844, "rdma_listen" },
	{ 0x2f287f0d, "copy_to_user" },
	{ 0x184f3575, "ib_copy_qp_attr_to_user" },
	{ 0xb4390f9a, "mcount" },
	{ 0x63bc5fcf, "rdma_notify" },
	{ 0xd36d011b, "mutex_lock" },
	{ 0x431f867f, "dev_get_by_index" },
	{ 0x4554df3d, "init_net" },
	{ 0xeb098ed4, "fput" },
	{ 0x4bcc009f, "rdma_create_id" },
	{ 0xb6588e7a, "idr_remove" },
	{ 0x835950c, "device_create_file" },
	{ 0x419ee6e8, "idr_pre_get" },
	{ 0xe6c994f2, "rdma_bind_addr" },
	{ 0xed1ce357, "rdma_resolve_route" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x4292364c, "schedule" },
	{ 0x299ee438, "rdma_disconnect" },
	{ 0x96ce6c46, "rdma_node_get_transport" },
	{ 0x8acb2c4e, "kmem_cache_alloc_trace" },
	{ 0x9f3f1640, "rdma_reject" },
	{ 0xe45f60d8, "__wake_up" },
	{ 0x37a0cba, "kfree" },
	{ 0x2e60bace, "memcpy" },
	{ 0x622fa02a, "prepare_to_wait" },
	{ 0xa34a49af, "rdma_set_service_type" },
	{ 0x6a85a3d, "fget" },
	{ 0x3ace5451, "rdma_resolve_addr" },
	{ 0x75bb675a, "finish_wait" },
	{ 0x19a9e62b, "complete" },
	{ 0xf6b6444b, "ib_sa_unpack_path" },
	{ 0xc26fe3ec, "register_net_sysctl" },
	{ 0x362ef408, "_copy_from_user" },
	{ 0xf12a5c83, "idr_find" },
	{ 0x92a05f3d, "idr_get_new" },
	{ 0x9c55118, "misc_deregister" },
	{ 0x6cdca3f8, "rdma_set_ib_paths" },
	{ 0x7ca1afc3, "rdma_leave_multicast" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=ib_core,rdma_cm,ib_uverbs,ib_sa";


MODULE_INFO(srcversion, "C3BC542CD7F1CE999CAAACB");
