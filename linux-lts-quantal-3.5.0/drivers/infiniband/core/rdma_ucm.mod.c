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
	{ 0xc1016642, "device_remove_file" },
	{ 0xff95a544, "kmalloc_caches" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0xd49af890, "rdma_port_get_link_layer" },
	{ 0xc8b57c27, "autoremove_wake_function" },
	{ 0x42a87a94, "unregister_net_sysctl_table" },
	{ 0x84babac4, "vlan_dev_vlan_id" },
	{ 0x78db38d3, "proc_dointvec" },
	{ 0x3bfbd926, "no_llseek" },
	{ 0x419b253a, "rdma_join_multicast" },
	{ 0x738d3726, "rdma_accept" },
	{ 0x18382f6a, "ib_copy_path_rec_to_user" },
	{ 0x97f4a250, "rdma_destroy_id" },
	{ 0xd35e9659, "mutex_unlock" },
	{ 0x7cf5a51, "ib_copy_ah_attr_to_user" },
	{ 0xa23b9a93, "rdma_init_qp_attr" },
	{ 0x91715312, "sprintf" },
	{ 0x4c1da3de, "nonseekable_open" },
	{ 0x494a735b, "rdma_connect" },
	{ 0x55688d7d, "rdma_set_reuseaddr" },
	{ 0x68dfc59f, "__init_waitqueue_head" },
	{ 0x3fa58ef8, "wait_for_completion" },
	{ 0xc8d5ef93, "misc_register" },
	{ 0x61536865, "idr_destroy" },
	{ 0x4c1cb91e, "current_task" },
	{ 0xfc629f82, "__mutex_init" },
	{ 0x50eedeb8, "printk" },
	{ 0x314a8116, "rdma_listen" },
	{ 0x2f287f0d, "copy_to_user" },
	{ 0x184f3575, "ib_copy_qp_attr_to_user" },
	{ 0xb4390f9a, "mcount" },
	{ 0xb7e2b392, "rdma_notify" },
	{ 0xd36d011b, "mutex_lock" },
	{ 0x730951df, "dev_get_by_index" },
	{ 0xb5f636b1, "init_net" },
	{ 0x58404e4d, "fput" },
	{ 0x6b31c653, "rdma_create_id" },
	{ 0xb6588e7a, "idr_remove" },
	{ 0x76fbc6e7, "device_create_file" },
	{ 0x419ee6e8, "idr_pre_get" },
	{ 0x299feb00, "rdma_bind_addr" },
	{ 0x4e5350fb, "rdma_resolve_route" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x4292364c, "schedule" },
	{ 0xcd929b2b, "rdma_disconnect" },
	{ 0x96ce6c46, "rdma_node_get_transport" },
	{ 0x496d7988, "kmem_cache_alloc_trace" },
	{ 0xf8f0de98, "rdma_reject" },
	{ 0xe45f60d8, "__wake_up" },
	{ 0x37a0cba, "kfree" },
	{ 0x2e60bace, "memcpy" },
	{ 0x622fa02a, "prepare_to_wait" },
	{ 0x8b80c9b, "rdma_set_service_type" },
	{ 0xa0c3e167, "fget" },
	{ 0x69de863, "rdma_resolve_addr" },
	{ 0x75bb675a, "finish_wait" },
	{ 0x19a9e62b, "complete" },
	{ 0xf6b6444b, "ib_sa_unpack_path" },
	{ 0x46a305e0, "register_net_sysctl" },
	{ 0x362ef408, "_copy_from_user" },
	{ 0xf12a5c83, "idr_find" },
	{ 0x92a05f3d, "idr_get_new" },
	{ 0x994cb0f7, "misc_deregister" },
	{ 0xb5320c12, "rdma_set_ib_paths" },
	{ 0xf714f69a, "rdma_leave_multicast" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=ib_core,rdma_cm,ib_uverbs,ib_sa";


MODULE_INFO(srcversion, "C3BC542CD7F1CE999CAAACB");
