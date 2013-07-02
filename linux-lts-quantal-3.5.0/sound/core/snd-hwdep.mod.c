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
	{ 0xc957f612, "snd_register_device_for_dev" },
	{ 0x4bda239c, "snd_card_unref" },
	{ 0x72c3cad, "snd_card_file_remove" },
	{ 0x3a013b7d, "remove_wait_queue" },
	{ 0xb2e5ae4a, "snd_lookup_minor_data" },
	{ 0x6729d3df, "__get_user_4" },
	{ 0x6339a8bc, "mutex_unlock" },
	{ 0x198788b4, "snd_lookup_oss_minor_data" },
	{ 0x91715312, "sprintf" },
	{ 0xf3298027, "snd_ctl_unregister_ioctl" },
	{ 0x68dfc59f, "__init_waitqueue_head" },
	{ 0xffd5a395, "default_wake_function" },
	{ 0xf58014ed, "snd_device_new" },
	{ 0x215f9a25, "current_task" },
	{ 0xc5c74531, "__mutex_init" },
	{ 0x50eedeb8, "printk" },
	{ 0x7a8b40fb, "snd_unregister_device" },
	{ 0xa1c76e0a, "_cond_resched" },
	{ 0x2f287f0d, "copy_to_user" },
	{ 0xb4390f9a, "mcount" },
	{ 0x73e20c1c, "strlcpy" },
	{ 0xcf510c4a, "mutex_lock" },
	{ 0x8f595b11, "snd_major" },
	{ 0x4b015768, "snd_iprintf" },
	{ 0xc5f0996, "module_put" },
	{ 0xb2fd5ceb, "__put_user_4" },
	{ 0x26a5823, "snd_card_file_add" },
	{ 0xfd7e771f, "snd_ctl_register_ioctl" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x4292364c, "schedule" },
	{ 0x9ca7a1fa, "snd_register_oss_device" },
	{ 0x7807eace, "kmem_cache_alloc_trace" },
	{ 0xe45f60d8, "__wake_up" },
	{ 0x7f427c58, "snd_unregister_oss_device" },
	{ 0xd7bd3af2, "add_wait_queue" },
	{ 0x37a0cba, "kfree" },
	{ 0x6514d1b3, "snd_info_free_entry" },
	{ 0x362ef408, "_copy_from_user" },
	{ 0x307bd854, "snd_info_create_module_entry" },
	{ 0x7b545f03, "snd_info_register" },
	{ 0x20ae0365, "try_module_get" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=snd";


MODULE_INFO(srcversion, "8AC52F3E4629A3BBFC28347");
