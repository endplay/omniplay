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
	{ 0x57f98c4b, "kmalloc_caches" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0x92ee6bb0, "snd_midi_event_reset_decode" },
	{ 0x9e7d3f0f, "snd_midi_event_reset_encode" },
	{ 0x15692c87, "param_ops_int" },
	{ 0x1a724fcc, "snd_seq_kernel_client_ctl" },
	{ 0xd35e9659, "mutex_unlock" },
	{ 0x2e944fc3, "snd_rawmidi_kernel_release" },
	{ 0x8c57686a, "snd_seq_create_kernel_client" },
	{ 0x16f73828, "snd_rawmidi_kernel_open" },
	{ 0x91715312, "sprintf" },
	{ 0x350963b4, "snd_midi_event_decode" },
	{ 0x56d66fcc, "snd_rawmidi_input_params" },
	{ 0xf2bf1549, "snd_midi_event_new" },
	{ 0x7b8699eb, "snd_seq_event_port_detach" },
	{ 0x50eedeb8, "printk" },
	{ 0xc622fb29, "snd_seq_device_unregister_driver" },
	{ 0xb0d5d3db, "snd_rawmidi_drain_output" },
	{ 0xb4390f9a, "mcount" },
	{ 0xd36d011b, "mutex_lock" },
	{ 0x2b51b084, "snd_midi_event_free" },
	{ 0x8cec0442, "snd_rawmidi_kernel_write" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x9e7692ce, "snd_seq_device_register_driver" },
	{ 0xad58d81e, "snd_rawmidi_kernel_read" },
	{ 0x8acb2c4e, "kmem_cache_alloc_trace" },
	{ 0x3a57f235, "snd_seq_autoload_unlock" },
	{ 0xe934da1d, "snd_seq_dump_var_event" },
	{ 0x605d19fd, "snd_rawmidi_output_params" },
	{ 0x37a0cba, "kfree" },
	{ 0x7f62d029, "snd_midi_event_encode" },
	{ 0x3fb4d161, "snd_seq_kernel_client_dispatch" },
	{ 0x6128b5fc, "__printk_ratelimit" },
	{ 0xb90668b2, "snd_seq_autoload_lock" },
	{ 0xb81960ca, "snprintf" },
	{ 0x6bb71038, "snd_seq_delete_kernel_client" },
	{ 0xf90e5a42, "snd_rawmidi_info_select" },
	{ 0xe914e41e, "strcpy" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=snd-seq-midi-event,snd-seq,snd-rawmidi,snd-seq-device";


MODULE_INFO(srcversion, "52D5F778F08904B57E0F06F");
