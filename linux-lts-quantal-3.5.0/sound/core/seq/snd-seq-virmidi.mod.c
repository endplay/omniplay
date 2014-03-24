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
	{ 0x9e7d3f0f, "snd_midi_event_reset_encode" },
	{ 0x86d5255f, "_raw_write_lock_irqsave" },
	{ 0x1a724fcc, "snd_seq_kernel_client_ctl" },
	{ 0x2aa09578, "snd_device_free" },
	{ 0xc01cf848, "_raw_read_lock" },
	{ 0x6d31cdc2, "snd_seq_create_kernel_client" },
	{ 0x816351fc, "snd_rawmidi_set_ops" },
	{ 0x91715312, "sprintf" },
	{ 0x350963b4, "snd_midi_event_decode" },
	{ 0x1cf7316b, "snd_rawmidi_new" },
	{ 0x168f1082, "_raw_write_unlock_irqrestore" },
	{ 0xf2bf1549, "snd_midi_event_new" },
	{ 0x50eedeb8, "printk" },
	{ 0xb4390f9a, "mcount" },
	{ 0x9560898b, "snd_rawmidi_transmit_peek" },
	{ 0x4213f57b, "module_put" },
	{ 0x2b51b084, "snd_midi_event_free" },
	{ 0xcb659bdf, "snd_rawmidi_transmit_ack" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x496d7988, "kmem_cache_alloc_trace" },
	{ 0xe934da1d, "snd_seq_dump_var_event" },
	{ 0x37a0cba, "kfree" },
	{ 0x7f62d029, "snd_midi_event_encode" },
	{ 0x3fb4d161, "snd_seq_kernel_client_dispatch" },
	{ 0x6bb71038, "snd_seq_delete_kernel_client" },
	{ 0xf7699001, "snd_rawmidi_receive" },
	{ 0xa49a6eba, "try_module_get" },
	{ 0xe914e41e, "strcpy" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=snd-seq-midi-event,snd-seq,snd,snd-rawmidi";


MODULE_INFO(srcversion, "A57E98328A5A3DC9FA4F7FB");
