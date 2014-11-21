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
	{ 0xf22fbdec, "module_layout" },
	{ 0x7e4581ef, "device_remove_file" },
	{ 0x91d0751, "kmalloc_caches" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0xe3e70f57, "rdma_port_get_link_layer" },
	{ 0xc8b57c27, "autoremove_wake_function" },
	{ 0x8f5e27b, "unregister_net_sysctl_table" },
	{ 0x3f0f6347, "vlan_dev_vlan_id" },
	{ 0xca1f0361, "proc_dointvec" },
	{ 0xd9bf79e8, "no_llseek" },
	{ 0x15bae949, "rdma_join_multicast" },
	{ 0x3c662d37, "rdma_accept" },
	{ 0x18382f6a, "ib_copy_path_rec_to_user" },
	{ 0x72a957df, "rdma_destroy_id" },
	{ 0xeb44738d, "mutex_unlock" },
	{ 0x7cf5a51, "ib_copy_ah_attr_to_user" },
	{ 0xb3279ded, "rdma_init_qp_attr" },
	{ 0x91715312, "sprintf" },
	{ 0x9d7beaec, "nonseekable_open" },
	{ 0x758f9d17, "rdma_connect" },
	{ 0x35306dc3, "rdma_set_reuseaddr" },
	{ 0xf3180fa5, "__init_waitqueue_head" },
	{ 0xd499df0e, "wait_for_completion" },
	{ 0x4fa01100, "misc_register" },
	{ 0xb294d0e, "idr_destroy" },
	{ 0x3a4fc05a, "current_task" },
	{ 0xa7541fd0, "__mutex_init" },
	{ 0x50eedeb8, "printk" },
	{ 0xa46fb658, "rdma_listen" },
	{ 0x2f287f0d, "copy_to_user" },
	{ 0x184f3575, "ib_copy_qp_attr_to_user" },
	{ 0xb4390f9a, "mcount" },
	{ 0x76ba4b6, "rdma_notify" },
	{ 0xfead291f, "mutex_lock" },
	{ 0x7fb0ee16, "dev_get_by_index" },
	{ 0x126821e4, "init_net" },
	{ 0x98b7d9ba, "fput" },
	{ 0xc3c02060, "rdma_create_id" },
	{ 0x60184917, "idr_remove" },
	{ 0xdc8b91b2, "device_create_file" },
	{ 0x39d6d2b0, "idr_pre_get" },
	{ 0xe1e79fa2, "rdma_bind_addr" },
	{ 0x94a60edb, "rdma_resolve_route" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x4292364c, "schedule" },
	{ 0xa261b9c4, "rdma_disconnect" },
	{ 0x96ce6c46, "rdma_node_get_transport" },
	{ 0xf327d4bf, "kmem_cache_alloc_trace" },
	{ 0x78cb4e5e, "rdma_reject" },
	{ 0xad74fae7, "__wake_up" },
	{ 0x37a0cba, "kfree" },
	{ 0x2e60bace, "memcpy" },
	{ 0x68cc45dd, "prepare_to_wait" },
	{ 0xf4d9c6bc, "rdma_set_service_type" },
	{ 0x4df9c8ef, "fget" },
	{ 0x46b184a4, "rdma_resolve_addr" },
	{ 0xf79d001, "finish_wait" },
	{ 0x11308c86, "complete" },
	{ 0xf6b6444b, "ib_sa_unpack_path" },
	{ 0x25d5af98, "register_net_sysctl" },
	{ 0x362ef408, "_copy_from_user" },
	{ 0x491ad563, "idr_find" },
	{ 0xc05be399, "idr_get_new" },
	{ 0xbab387ce, "misc_deregister" },
	{ 0x90d6c2aa, "rdma_set_ib_paths" },
	{ 0x2a54c434, "rdma_leave_multicast" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=ib_core,rdma_cm,ib_uverbs,ib_sa";


MODULE_INFO(srcversion, "C3BC542CD7F1CE999CAAACB");
