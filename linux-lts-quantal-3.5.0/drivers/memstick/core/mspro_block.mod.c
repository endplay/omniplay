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
	{ 0x15692c87, "param_ops_int" },
	{ 0x61536865, "idr_destroy" },
	{ 0x83b4ae3, "memstick_unregister_driver" },
	{ 0xb5a459dc, "unregister_blkdev" },
	{ 0x8db7189a, "memstick_register_driver" },
	{ 0x71a50dbc, "register_blkdev" },
	{ 0xb868c76b, "add_disk" },
	{ 0x84a33f84, "blk_queue_logical_block_size" },
	{ 0x91715312, "sprintf" },
	{ 0xcbf58d75, "blk_queue_max_segment_size" },
	{ 0x464e5720, "blk_queue_max_segments" },
	{ 0xaf283e5a, "blk_queue_max_hw_sectors" },
	{ 0xd2ced37e, "blk_queue_bounce_limit" },
	{ 0xfa47ae72, "blk_queue_prep_rq" },
	{ 0x92f403a6, "blk_init_queue" },
	{ 0x56512096, "alloc_disk" },
	{ 0x92a05f3d, "idr_get_new" },
	{ 0x419ee6e8, "idr_pre_get" },
	{ 0x1163f0a7, "blk_max_low_pfn" },
	{ 0x82771744, "sysfs_create_group" },
	{ 0xb81960ca, "snprintf" },
	{ 0x2e60bace, "memcpy" },
	{ 0xb6244511, "sg_init_one" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0x50eedeb8, "printk" },
	{ 0xf9a482f9, "msleep" },
	{ 0x750d888b, "memstick_set_rw_addr" },
	{ 0x7807eace, "kmem_cache_alloc_trace" },
	{ 0x440a4045, "kmalloc_caches" },
	{ 0x646e8726, "__blk_end_request_all" },
	{ 0xb840f7fd, "dev_set_drvdata" },
	{ 0x72c93d7f, "sysfs_remove_group" },
	{ 0xb6f1aa81, "blk_cleanup_queue" },
	{ 0xbe091077, "del_gendisk" },
	{ 0x395c7095, "blk_dump_rq_flags" },
	{ 0x5d820a02, "memstick_init_req_sg" },
	{ 0xfc9c80e4, "mem_map" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0xf9e73082, "scnprintf" },
	{ 0xa7239558, "__blk_end_request" },
	{ 0x128a5cf9, "complete_all" },
	{ 0x96f229a7, "__blk_end_request_cur" },
	{ 0xd6e16fcb, "blk_rq_map_sg" },
	{ 0xeae07c3d, "blk_fetch_request" },
	{ 0x3fa58ef8, "wait_for_completion" },
	{ 0xa8a4d157, "memstick_new_req" },
	{ 0xa5987a36, "memstick_init_req" },
	{ 0xb2e93f2, "put_disk" },
	{ 0xb6588e7a, "idr_remove" },
	{ 0x37a0cba, "kfree" },
	{ 0x6339a8bc, "mutex_unlock" },
	{ 0xcf510c4a, "mutex_lock" },
	{ 0xd84eec9, "blk_stop_queue" },
	{ 0xf97456ea, "_raw_spin_unlock_irqrestore" },
	{ 0x138640c3, "blk_start_queue" },
	{ 0x21fb443e, "_raw_spin_lock_irqsave" },
	{ 0x42da990e, "dev_get_drvdata" },
	{ 0xb4390f9a, "mcount" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=memstick";


MODULE_INFO(srcversion, "C739EA42D131D96DED6B9F1");
