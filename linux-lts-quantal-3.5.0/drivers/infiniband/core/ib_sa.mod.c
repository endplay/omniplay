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
	{ 0xff95a544, "kmalloc_caches" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0xe1aac1c3, "ib_find_cached_gid" },
	{ 0x76ebea8, "pv_lock_ops" },
	{ 0x43a53735, "__alloc_workqueue_key" },
	{ 0xd49af890, "rdma_port_get_link_layer" },
	{ 0x95af2eb9, "ib_find_pkey" },
	{ 0x79aa04a2, "get_random_bytes" },
	{ 0x2fab0a87, "ib_register_mad_agent" },
	{ 0x6bbe84e5, "ib_free_recv_mad" },
	{ 0x33543801, "queue_work" },
	{ 0x520b2638, "ib_pack" },
	{ 0x33e3f5e0, "ib_destroy_ah" },
	{ 0xb8aad78a, "ib_free_send_mad" },
	{ 0xfbe27a1c, "rb_first" },
	{ 0x68dfc59f, "__init_waitqueue_head" },
	{ 0x3fa58ef8, "wait_for_completion" },
	{ 0x61536865, "idr_destroy" },
	{ 0xf97456ea, "_raw_spin_unlock_irqrestore" },
	{ 0x50eedeb8, "printk" },
	{ 0x5152e605, "memcmp" },
	{ 0xedb144e1, "ib_get_client_data" },
	{ 0xc0580937, "rb_erase" },
	{ 0xb4390f9a, "mcount" },
	{ 0xa05e93f9, "ib_query_port" },
	{ 0x16305289, "warn_slowpath_null" },
	{ 0x8c03d20c, "destroy_workqueue" },
	{ 0xb91507bc, "ib_set_client_data" },
	{ 0x42160169, "flush_workqueue" },
	{ 0x37e98ffb, "ib_create_send_mad" },
	{ 0x506e9f7f, "ib_post_send_mad" },
	{ 0xb6588e7a, "idr_remove" },
	{ 0x8b31cefe, "ib_unregister_mad_agent" },
	{ 0x419ee6e8, "idr_pre_get" },
	{ 0xa1534f27, "ib_register_client" },
	{ 0xd8efd162, "ib_create_ah" },
	{ 0xb572363f, "ib_unregister_event_handler" },
	{ 0x8ff4079b, "pv_irq_ops" },
	{ 0x5c4af8cf, "ib_register_event_handler" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0xf1faac3a, "_raw_spin_lock_irq" },
	{ 0x551f9246, "ib_cancel_mad" },
	{ 0x96ce6c46, "rdma_node_get_transport" },
	{ 0x496d7988, "kmem_cache_alloc_trace" },
	{ 0x67f7403e, "_raw_spin_lock" },
	{ 0x21fb443e, "_raw_spin_lock_irqsave" },
	{ 0xa6dcc773, "rb_insert_color" },
	{ 0x37a0cba, "kfree" },
	{ 0xb1a312e1, "ib_unpack" },
	{ 0xbdf5c25c, "rb_next" },
	{ 0x19a9e62b, "complete" },
	{ 0xdbd019c4, "ib_wq" },
	{ 0xf12a5c83, "idr_find" },
	{ 0x92a05f3d, "idr_get_new" },
	{ 0x19aef1a3, "ib_unregister_client" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=ib_core,ib_mad";


MODULE_INFO(srcversion, "72D43BD04A27D98620F2F9A");
