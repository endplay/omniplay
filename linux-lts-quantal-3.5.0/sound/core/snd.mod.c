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
	{ 0x6bc3fbc0, "__unregister_chrdev" },
	{ 0x402b8281, "__request_module" },
	{ 0xff95a544, "kmalloc_caches" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0x2ac6bc85, "put_pid" },
	{ 0x72df2f2a, "up_read" },
	{ 0xd6ee688f, "vmalloc" },
	{ 0x76ebea8, "pv_lock_ops" },
	{ 0x15692c87, "param_ops_int" },
	{ 0x29c3986b, "proc_symlink" },
	{ 0xd0d8621b, "strlen" },
	{ 0x4acd93d3, "release_resource" },
	{ 0xbf0a8a15, "sound_class" },
	{ 0x86d5255f, "_raw_write_lock_irqsave" },
	{ 0xc8b57c27, "autoremove_wake_function" },
	{ 0xdb95a99, "pid_vnr" },
	{ 0x3a013b7d, "remove_wait_queue" },
	{ 0x3bfbd926, "no_llseek" },
	{ 0xc01cf848, "_raw_read_lock" },
	{ 0x3ad70291, "remove_proc_entry" },
	{ 0xb0f0d236, "device_destroy" },
	{ 0x6729d3df, "__get_user_4" },
	{ 0x1571c46d, "__register_chrdev" },
	{ 0xd35e9659, "mutex_unlock" },
	{ 0x999e8297, "vfree" },
	{ 0x91715312, "sprintf" },
	{ 0xc499ae1e, "kstrdup" },
	{ 0x4c1da3de, "nonseekable_open" },
	{ 0xe2d5255a, "strcmp" },
	{ 0xd0f0d945, "down_read" },
	{ 0x168f1082, "_raw_write_unlock_irqrestore" },
	{ 0x18986345, "input_event" },
	{ 0x68dfc59f, "__init_waitqueue_head" },
	{ 0xffd5a395, "default_wake_function" },
	{ 0xf82abc1d, "isa_dma_bridge_buggy" },
	{ 0x35b6b772, "param_ops_charp" },
	{ 0xfa9d9a8f, "proc_mkdir" },
	{ 0x11089ac7, "_ctype" },
	{ 0xf97456ea, "_raw_spin_unlock_irqrestore" },
	{ 0x4c1cb91e, "current_task" },
	{ 0xfc629f82, "__mutex_init" },
	{ 0x50eedeb8, "printk" },
	{ 0x5152e605, "memcmp" },
	{ 0x7c1372e8, "panic" },
	{ 0xa1c76e0a, "_cond_resched" },
	{ 0x2f287f0d, "copy_to_user" },
	{ 0x1c7e0d4d, "fasync_helper" },
	{ 0xb4390f9a, "mcount" },
	{ 0x6d2f086, "dma_spin_lock" },
	{ 0x6c2e3320, "strncmp" },
	{ 0x73e20c1c, "strlcpy" },
	{ 0x6bc03f3c, "input_set_capability" },
	{ 0x16305289, "warn_slowpath_null" },
	{ 0xd36d011b, "mutex_lock" },
	{ 0x1e6d26a8, "strstr" },
	{ 0xce306ae6, "noop_llseek" },
	{ 0x4f220c3f, "device_create" },
	{ 0x89ff43f6, "init_uts_ns" },
	{ 0xbc1afedf, "up_write" },
	{ 0x61b5ade0, "down_write" },
	{ 0x61651be, "strcat" },
	{ 0x76fbc6e7, "device_create_file" },
	{ 0x4213f57b, "module_put" },
	{ 0x8ff4079b, "pv_irq_ops" },
	{ 0xd4d06855, "register_sound_special_device" },
	{ 0xb2fd5ceb, "__put_user_4" },
	{ 0x738803e6, "strnlen" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x3b46f8c8, "input_register_device" },
	{ 0x4292364c, "schedule" },
	{ 0xd62c833f, "schedule_timeout" },
	{ 0xf1faac3a, "_raw_spin_lock_irq" },
	{ 0x94f55dc4, "input_free_device" },
	{ 0xc05e58cb, "create_proc_entry" },
	{ 0x496d7988, "kmem_cache_alloc_trace" },
	{ 0x67f7403e, "_raw_spin_lock" },
	{ 0x21fb443e, "_raw_spin_lock_irqsave" },
	{ 0x7afa89fc, "vsnprintf" },
	{ 0xe45f60d8, "__wake_up" },
	{ 0xd7bd3af2, "add_wait_queue" },
	{ 0x37a0cba, "kfree" },
	{ 0x2e60bace, "memcpy" },
	{ 0x728abd4a, "input_unregister_device" },
	{ 0x622fa02a, "prepare_to_wait" },
	{ 0x4845c423, "param_array_ops" },
	{ 0x99c95fa5, "unregister_sound_special" },
	{ 0x1c02b222, "kill_fasync" },
	{ 0x75bb675a, "finish_wait" },
	{ 0x1de9da1d, "device_unregister" },
	{ 0xe2e8065e, "memdup_user" },
	{ 0xb81960ca, "snprintf" },
	{ 0x362ef408, "_copy_from_user" },
	{ 0xad7bed17, "dev_get_drvdata" },
	{ 0x657879ce, "__init_rwsem" },
	{ 0xa49a6eba, "try_module_get" },
	{ 0xc2d711e1, "krealloc" },
	{ 0xe914e41e, "strcpy" },
	{ 0x95a39d71, "input_allocate_device" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=soundcore";


MODULE_INFO(srcversion, "824D1348E6C9F065B17B3E5");
