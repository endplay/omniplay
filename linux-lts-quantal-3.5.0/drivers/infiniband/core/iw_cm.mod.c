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
	{ 0x440a4045, "kmalloc_caches" },
	{ 0x43a53735, "__alloc_workqueue_key" },
	{ 0xc8b57c27, "autoremove_wake_function" },
	{ 0x33543801, "queue_work" },
	{ 0xe2fae716, "kmemdup" },
	{ 0x49b5e902, "ib_modify_qp" },
	{ 0x68dfc59f, "__init_waitqueue_head" },
	{ 0x3fa58ef8, "wait_for_completion" },
	{ 0xf97456ea, "_raw_spin_unlock_irqrestore" },
	{ 0x215f9a25, "current_task" },
	{ 0xb4390f9a, "mcount" },
	{ 0x8c03d20c, "destroy_workqueue" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x4292364c, "schedule" },
	{ 0x7807eace, "kmem_cache_alloc_trace" },
	{ 0x21fb443e, "_raw_spin_lock_irqsave" },
	{ 0xe45f60d8, "__wake_up" },
	{ 0x37a0cba, "kfree" },
	{ 0x622fa02a, "prepare_to_wait" },
	{ 0x75bb675a, "finish_wait" },
	{ 0x19a9e62b, "complete" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=ib_core";


MODULE_INFO(srcversion, "8C6E4C260AEB4E0933752BA");
