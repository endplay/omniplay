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
	{ 0x86c0f66d, "driver_register" },
	{ 0x1b242b69, "__bus_register" },
	{ 0x76ebea8, "pv_lock_ops" },
	{ 0x43a53735, "__alloc_workqueue_key" },
	{ 0x33543801, "queue_work" },
	{ 0xd35e9659, "mutex_unlock" },
	{ 0x91715312, "sprintf" },
	{ 0x68dfc59f, "__init_waitqueue_head" },
	{ 0x3fa58ef8, "wait_for_completion" },
	{ 0x61536865, "idr_destroy" },
	{ 0xb531ae68, "device_del" },
	{ 0xffdb343b, "device_register" },
	{ 0xfc629f82, "__mutex_init" },
	{ 0x483681b6, "class_unregister" },
	{ 0xaafbc7ff, "driver_unregister" },
	{ 0xb4390f9a, "mcount" },
	{ 0xd36d011b, "mutex_lock" },
	{ 0x8c03d20c, "destroy_workqueue" },
	{ 0x7ad8b935, "device_add" },
	{ 0x98ae5de4, "__class_register" },
	{ 0x12d544f5, "bus_unregister" },
	{ 0x42160169, "flush_workqueue" },
	{ 0xb6588e7a, "idr_remove" },
	{ 0x419ee6e8, "idr_pre_get" },
	{ 0x3b478612, "put_device" },
	{ 0x496d7988, "kmem_cache_alloc_trace" },
	{ 0x67f7403e, "_raw_spin_lock" },
	{ 0xf678435, "get_device" },
	{ 0x37a0cba, "kfree" },
	{ 0x2e60bace, "memcpy" },
	{ 0xb407b43c, "device_initialize" },
	{ 0x1de9da1d, "device_unregister" },
	{ 0x19a9e62b, "complete" },
	{ 0xdafbef85, "dev_set_name" },
	{ 0x6d044c26, "param_ops_uint" },
	{ 0x92a05f3d, "idr_get_new" },
	{ 0xa7f92105, "add_uevent_var" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "5E80579A84C7BFB00BAC744");
