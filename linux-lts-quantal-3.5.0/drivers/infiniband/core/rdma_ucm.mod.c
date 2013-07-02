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
	{ 0xab702499, "device_remove_file" },
	{ 0x440a4045, "kmalloc_caches" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0xd49af890, "rdma_port_get_link_layer" },
	{ 0xc8b57c27, "autoremove_wake_function" },
	{ 0xca64fb0c, "unregister_net_sysctl_table" },
	{ 0x8ec9c003, "vlan_dev_vlan_id" },
	{ 0x78db38d3, "proc_dointvec" },
	{ 0x1e06b4b3, "no_llseek" },
	{ 0x8c8768d8, "rdma_join_multicast" },
	{ 0xb6499e33, "rdma_accept" },
	{ 0x18382f6a, "ib_copy_path_rec_to_user" },
	{ 0x7d3f7aa0, "rdma_destroy_id" },
	{ 0x6339a8bc, "mutex_unlock" },
	{ 0x7cf5a51, "ib_copy_ah_attr_to_user" },
	{ 0xb709b779, "rdma_init_qp_attr" },
	{ 0x91715312, "sprintf" },
	{ 0x2bc2ec5e, "nonseekable_open" },
	{ 0x25e1d655, "rdma_connect" },
	{ 0xf6b76312, "rdma_set_reuseaddr" },
	{ 0x68dfc59f, "__init_waitqueue_head" },
	{ 0x3fa58ef8, "wait_for_completion" },
	{ 0x31e0d0f0, "misc_register" },
	{ 0x61536865, "idr_destroy" },
	{ 0x215f9a25, "current_task" },
	{ 0xc5c74531, "__mutex_init" },
	{ 0x50eedeb8, "printk" },
	{ 0x70a30090, "rdma_listen" },
	{ 0x2f287f0d, "copy_to_user" },
	{ 0x184f3575, "ib_copy_qp_attr_to_user" },
	{ 0xb4390f9a, "mcount" },
	{ 0x9e860fe0, "rdma_notify" },
	{ 0xcf510c4a, "mutex_lock" },
	{ 0xeabe5201, "dev_get_by_index" },
	{ 0x95f3164e, "init_net" },
	{ 0xfde963c0, "fput" },
	{ 0x7ea33ca9, "rdma_create_id" },
	{ 0xb6588e7a, "idr_remove" },
	{ 0x68fe086e, "device_create_file" },
	{ 0x419ee6e8, "idr_pre_get" },
	{ 0xa594d8b9, "rdma_bind_addr" },
	{ 0x6d37a427, "rdma_resolve_route" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x4292364c, "schedule" },
	{ 0x4d400d29, "rdma_disconnect" },
	{ 0x96ce6c46, "rdma_node_get_transport" },
	{ 0x7807eace, "kmem_cache_alloc_trace" },
	{ 0x2a800a47, "rdma_reject" },
	{ 0xe45f60d8, "__wake_up" },
	{ 0x37a0cba, "kfree" },
	{ 0x2e60bace, "memcpy" },
	{ 0x622fa02a, "prepare_to_wait" },
	{ 0x47a949ed, "rdma_set_service_type" },
	{ 0x3bb2d799, "fget" },
	{ 0x3dfd2a2d, "rdma_resolve_addr" },
	{ 0x75bb675a, "finish_wait" },
	{ 0x19a9e62b, "complete" },
	{ 0xf6b6444b, "ib_sa_unpack_path" },
	{ 0xdf55515, "register_net_sysctl" },
	{ 0x362ef408, "_copy_from_user" },
	{ 0xf12a5c83, "idr_find" },
	{ 0x92a05f3d, "idr_get_new" },
	{ 0x9c55118, "misc_deregister" },
	{ 0xae1f3c46, "rdma_set_ib_paths" },
	{ 0xefecea53, "rdma_leave_multicast" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=ib_core,rdma_cm,ib_uverbs,ib_sa";


MODULE_INFO(srcversion, "C3BC542CD7F1CE999CAAACB");
