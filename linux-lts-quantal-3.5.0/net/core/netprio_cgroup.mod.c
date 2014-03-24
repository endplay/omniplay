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
	{ 0xc2cdbf1, "synchronize_sched" },
	{ 0xd39166a0, "cgroup_unload_subsys" },
	{ 0xfe769456, "unregister_netdevice_notifier" },
	{ 0x63ecad53, "register_netdevice_notifier" },
	{ 0x9a766ac, "cgroup_load_subsys" },
	{ 0xf11543ff, "find_first_zero_bit" },
	{ 0x496d7988, "kmem_cache_alloc_trace" },
	{ 0xff95a544, "kmalloc_caches" },
	{ 0xae71b296, "dev_get_by_name" },
	{ 0x54a9db5f, "_kstrtoul" },
	{ 0x1e6d26a8, "strstr" },
	{ 0xd0d8621b, "strlen" },
	{ 0xc499ae1e, "kstrdup" },
	{ 0x50eedeb8, "printk" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0x50f5e532, "call_rcu_sched" },
	{ 0x37a0cba, "kfree" },
	{ 0x6e720ff2, "rtnl_unlock" },
	{ 0xc7a4fbed, "rtnl_lock" },
	{ 0xf97456ea, "_raw_spin_unlock_irqrestore" },
	{ 0x21fb443e, "_raw_spin_lock_irqsave" },
	{ 0xb5f636b1, "init_net" },
	{ 0x4b56cd2e, "net_prio_subsys_id" },
	{ 0xb4390f9a, "mcount" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "8C651BE23984F29CAE13B1F");
