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
	{ 0x7406f5c5, "kobject_put" },
	{ 0x57f98c4b, "kmalloc_caches" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0xe1aac1c3, "ib_find_cached_gid" },
	{ 0x44887d81, "ib_create_ah_from_wc" },
	{ 0x76ebea8, "pv_lock_ops" },
	{ 0xf2edb80d, "ib_modify_mad" },
	{ 0x86d5255f, "_raw_write_lock_irqsave" },
	{ 0x43a53735, "__alloc_workqueue_key" },
	{ 0x79aa04a2, "get_random_bytes" },
	{ 0x2fab0a87, "ib_register_mad_agent" },
	{ 0x6bbe84e5, "ib_free_recv_mad" },
	{ 0x23d1a8b1, "ib_init_ah_from_path" },
	{ 0xe2fae716, "kmemdup" },
	{ 0xfb0e29f, "init_timer_key" },
	{ 0x91715312, "sprintf" },
	{ 0x2ca7bbef, "ib_get_cached_gid" },
	{ 0x33e3f5e0, "ib_destroy_ah" },
	{ 0x168f1082, "_raw_write_unlock_irqrestore" },
	{ 0x733c3b54, "kasprintf" },
	{ 0xb8aad78a, "ib_free_send_mad" },
	{ 0x68dfc59f, "__init_waitqueue_head" },
	{ 0x3fa58ef8, "wait_for_completion" },
	{ 0xd5f2172f, "del_timer_sync" },
	{ 0x61536865, "idr_destroy" },
	{ 0xf97456ea, "_raw_spin_unlock_irqrestore" },
	{ 0xddea3160, "ib_query_device" },
	{ 0x5152e605, "memcmp" },
	{ 0x612a8ef9, "class_unregister" },
	{ 0x69a19375, "kobject_init_and_add" },
	{ 0xedb144e1, "ib_get_client_data" },
	{ 0xc0580937, "rb_erase" },
	{ 0xb4390f9a, "mcount" },
	{ 0x8c03d20c, "destroy_workqueue" },
	{ 0xcef62c7b, "device_create" },
	{ 0x40f402b6, "ib_init_ah_from_wc" },
	{ 0x4fa75363, "__class_register" },
	{ 0xb91507bc, "ib_set_client_data" },
	{ 0x42160169, "flush_workqueue" },
	{ 0x37e98ffb, "ib_create_send_mad" },
	{ 0x506e9f7f, "ib_post_send_mad" },
	{ 0xb6588e7a, "idr_remove" },
	{ 0x8b31cefe, "ib_unregister_mad_agent" },
	{ 0x419ee6e8, "idr_pre_get" },
	{ 0xa1534f27, "ib_register_client" },
	{ 0xd8efd162, "ib_create_ah" },
	{ 0x8ff4079b, "pv_irq_ops" },
	{ 0x1790d76b, "_raw_read_lock_irqsave" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x3bd1b1f6, "msecs_to_jiffies" },
	{ 0xf1faac3a, "_raw_spin_lock_irq" },
	{ 0x762e69f3, "ib_find_cached_pkey" },
	{ 0x703b4352, "_raw_read_unlock_irqrestore" },
	{ 0x551f9246, "ib_cancel_mad" },
	{ 0x96ce6c46, "rdma_node_get_transport" },
	{ 0x8acb2c4e, "kmem_cache_alloc_trace" },
	{ 0x67f7403e, "_raw_spin_lock" },
	{ 0x21fb443e, "_raw_spin_lock_irqsave" },
	{ 0xa6dcc773, "rb_insert_color" },
	{ 0x96e79739, "idr_get_new_above" },
	{ 0xdccda88b, "ib_modify_port" },
	{ 0x37a0cba, "kfree" },
	{ 0x2e60bace, "memcpy" },
	{ 0x27f9e856, "device_unregister" },
	{ 0x19a9e62b, "complete" },
	{ 0xcb451e56, "idr_init" },
	{ 0xf12a5c83, "idr_find" },
	{ 0x19aef1a3, "ib_unregister_client" },
	{ 0x47c149ab, "queue_delayed_work" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=ib_core,ib_mad,ib_sa";


MODULE_INFO(srcversion, "D645504C55495598E4D041F");
