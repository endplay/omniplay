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
	{ 0x9ab5b95a, "kmem_cache_destroy" },
	{ 0x440a4045, "kmalloc_caches" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0x5422da6b, "ib_get_cached_lmc" },
	{ 0xfc9c80e4, "mem_map" },
	{ 0x44887d81, "ib_create_ah_from_wc" },
	{ 0x15692c87, "param_ops_int" },
	{ 0xc996d097, "del_timer" },
	{ 0xdbf506b8, "ib_dealloc_pd" },
	{ 0x43a53735, "__alloc_workqueue_key" },
	{ 0xd49af890, "rdma_port_get_link_layer" },
	{ 0xc69d007a, "ib_destroy_qp" },
	{ 0xc0a3d105, "find_next_bit" },
	{ 0x33543801, "queue_work" },
	{ 0xe2fae716, "kmemdup" },
	{ 0xfb0e29f, "init_timer_key" },
	{ 0x7d11c268, "jiffies" },
	{ 0x2ca7bbef, "ib_get_cached_gid" },
	{ 0x33e3f5e0, "ib_destroy_ah" },
	{ 0x49b5e902, "ib_modify_qp" },
	{ 0x68dfc59f, "__init_waitqueue_head" },
	{ 0xa6d972a3, "ib_create_qp" },
	{ 0x3fa58ef8, "wait_for_completion" },
	{ 0x759cf34c, "ib_alloc_pd" },
	{ 0xd5f2172f, "del_timer_sync" },
	{ 0x2bc95bd4, "memset" },
	{ 0xf97456ea, "_raw_spin_unlock_irqrestore" },
	{ 0xbae1f7a5, "ib_get_dma_mr" },
	{ 0x50eedeb8, "printk" },
	{ 0x5152e605, "memcmp" },
	{ 0xb4390f9a, "mcount" },
	{ 0x8978b112, "kmem_cache_free" },
	{ 0x8c03d20c, "destroy_workqueue" },
	{ 0x42160169, "flush_workqueue" },
	{ 0x7042e52f, "ib_destroy_cq" },
	{ 0xa1534f27, "ib_register_client" },
	{ 0x1a37f588, "kmem_cache_alloc" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x3bd1b1f6, "msecs_to_jiffies" },
	{ 0x96ce6c46, "rdma_node_get_transport" },
	{ 0x7807eace, "kmem_cache_alloc_trace" },
	{ 0x21fb443e, "_raw_spin_lock_irqsave" },
	{ 0x5dedaced, "kmem_cache_create" },
	{ 0xd2d909c4, "ib_dereg_mr" },
	{ 0x37a0cba, "kfree" },
	{ 0x2e60bace, "memcpy" },
	{ 0xb352177e, "find_first_bit" },
	{ 0x844dee28, "ib_create_cq" },
	{ 0x546f7a5e, "ib_query_ah" },
	{ 0x19a9e62b, "complete" },
	{ 0xb81960ca, "snprintf" },
	{ 0x19aef1a3, "ib_unregister_client" },
	{ 0x47c149ab, "queue_delayed_work" },
	{ 0x31944a28, "dma_ops" },
	{ 0xc2d711e1, "krealloc" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=ib_core";


MODULE_INFO(srcversion, "EF90EEA25C886DDC52FFF7E");
