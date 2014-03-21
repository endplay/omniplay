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
	{ 0xf9a482f9, "msleep" },
	{ 0x2ac6bc85, "put_pid" },
	{ 0x6e52ce12, "snd_device_register" },
	{ 0x76ebea8, "pv_lock_ops" },
	{ 0x15692c87, "param_ops_int" },
	{ 0xb41d3ae6, "snd_register_device_for_dev" },
	{ 0xcd680a86, "snd_card_unref" },
	{ 0xc8b57c27, "autoremove_wake_function" },
	{ 0x48f77908, "snd_card_file_remove" },
	{ 0xdb95a99, "pid_vnr" },
	{ 0x3a013b7d, "remove_wait_queue" },
	{ 0x3bfbd926, "no_llseek" },
	{ 0xc01cf848, "_raw_read_lock" },
	{ 0x77aa089b, "snd_info_create_card_entry" },
	{ 0x8949858b, "schedule_work" },
	{ 0xb2e5ae4a, "snd_lookup_minor_data" },
	{ 0x4205ad24, "cancel_work_sync" },
	{ 0x6729d3df, "__get_user_4" },
	{ 0xd35e9659, "mutex_unlock" },
	{ 0x198788b4, "snd_lookup_oss_minor_data" },
	{ 0x91715312, "sprintf" },
	{ 0x4c1da3de, "nonseekable_open" },
	{ 0x75963f26, "snd_ctl_unregister_ioctl" },
	{ 0x68dfc59f, "__init_waitqueue_head" },
	{ 0xffd5a395, "default_wake_function" },
	{ 0x827e959c, "snd_device_new" },
	{ 0xf97456ea, "_raw_spin_unlock_irqrestore" },
	{ 0x4c1cb91e, "current_task" },
	{ 0xfc629f82, "__mutex_init" },
	{ 0x50eedeb8, "printk" },
	{ 0x9c5d9389, "snd_unregister_device" },
	{ 0x8df3789f, "snd_oss_info_register" },
	{ 0xa1c76e0a, "_cond_resched" },
	{ 0x2f287f0d, "copy_to_user" },
	{ 0xb4390f9a, "mcount" },
	{ 0x73e20c1c, "strlcpy" },
	{ 0xd36d011b, "mutex_lock" },
	{ 0x8f595b11, "snd_major" },
	{ 0x4b015768, "snd_iprintf" },
	{ 0x4213f57b, "module_put" },
	{ 0x8ff4079b, "pv_irq_ops" },
	{ 0xb2fd5ceb, "__put_user_4" },
	{ 0xe094f16d, "snd_card_file_add" },
	{ 0x8dac01aa, "snd_ctl_register_ioctl" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x4292364c, "schedule" },
	{ 0xd62c833f, "schedule_timeout" },
	{ 0xf1faac3a, "_raw_spin_lock_irq" },
	{ 0x8feb4865, "snd_register_oss_device" },
	{ 0x496d7988, "kmem_cache_alloc_trace" },
	{ 0x21fb443e, "_raw_spin_lock_irqsave" },
	{ 0xe45f60d8, "__wake_up" },
	{ 0xed0afa7e, "snd_unregister_oss_device" },
	{ 0xd7bd3af2, "add_wait_queue" },
	{ 0x37a0cba, "kfree" },
	{ 0x2e60bace, "memcpy" },
	{ 0xeaf57edb, "snd_info_free_entry" },
	{ 0x622fa02a, "prepare_to_wait" },
	{ 0x4845c423, "param_array_ops" },
	{ 0x75bb675a, "finish_wait" },
	{ 0x40459a9b, "snd_seq_device_new" },
	{ 0x362ef408, "_copy_from_user" },
	{ 0xfffc0a23, "snd_info_register" },
	{ 0xa49a6eba, "try_module_get" },
	{ 0xc2d711e1, "krealloc" },
	{ 0xe914e41e, "strcpy" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=snd,snd-seq-device";


MODULE_INFO(srcversion, "9C2A8D721BE25EBEE5788E5");
