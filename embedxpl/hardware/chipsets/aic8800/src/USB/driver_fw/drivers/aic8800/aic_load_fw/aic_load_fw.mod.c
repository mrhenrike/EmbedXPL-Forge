#include <linux/module.h>
#include <linux/export-internal.h>
#include <linux/compiler.h>

MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

KSYMTAB_FUNC(get_fw_path, "", "");
KSYMTAB_FUNC(get_testmode, "", "");
KSYMTAB_FUNC(set_testmode, "", "");
KSYMTAB_FUNC(get_hardware_info, "", "");
KSYMTAB_FUNC(get_adap_test, "", "");
KSYMTAB_FUNC(get_flash_bin_size, "", "");
KSYMTAB_FUNC(get_flash_bin_crc, "", "");
KSYMTAB_FUNC(get_userconfig_xtal_cap, "", "");
KSYMTAB_FUNC(get_userconfig_txpwr_idx, "", "");
KSYMTAB_FUNC(get_userconfig_txpwr_ofst, "", "");
KSYMTAB_FUNC(aicwf_rxbuff_size_get, "", "");
KSYMTAB_FUNC(aicwf_prealloc_rxbuff_alloc, "", "");
KSYMTAB_FUNC(aicwf_prealloc_rxbuff_free, "", "");
KSYMTAB_FUNC(aicwf_prealloc_txq_alloc, "", "");

SYMBOL_CRC(get_fw_path, 0x0e95ec6a, "");
SYMBOL_CRC(get_testmode, 0x7851be11, "");
SYMBOL_CRC(set_testmode, 0x40c76f23, "");
SYMBOL_CRC(get_hardware_info, 0x7851be11, "");
SYMBOL_CRC(get_adap_test, 0x7851be11, "");
SYMBOL_CRC(get_flash_bin_size, 0x7851be11, "");
SYMBOL_CRC(get_flash_bin_crc, 0xc01aafd2, "");
SYMBOL_CRC(get_userconfig_xtal_cap, 0xf98b9154, "");
SYMBOL_CRC(get_userconfig_txpwr_idx, 0x5262df42, "");
SYMBOL_CRC(get_userconfig_txpwr_ofst, 0x586d1f60, "");
SYMBOL_CRC(aicwf_rxbuff_size_get, 0x7851be11, "");
SYMBOL_CRC(aicwf_prealloc_rxbuff_alloc, 0x11fd4e2a, "");
SYMBOL_CRC(aicwf_prealloc_rxbuff_free, 0xcbcbbfe0, "");
SYMBOL_CRC(aicwf_prealloc_txq_alloc, 0xfb44bbd0, "");

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xcbf03397, "usb_register_driver" },
	{ 0xb2fa43dd, "kernel_sigaction" },
	{ 0xfbe7861b, "memcpy" },
	{ 0xcb8b6ec6, "kfree" },
	{ 0xc281f1fb, "prepare_to_wait_event" },
	{ 0x5e505530, "kthread_should_stop" },
	{ 0x68a1b6c6, "__wake_up" },
	{ 0x11f4259a, "_raw_spin_lock_irqsave" },
	{ 0x5af09d8b, "_raw_spin_lock" },
	{ 0xd272d446, "__fentry__" },
	{ 0x4f51989c, "wake_up_process" },
	{ 0x5a844b26, "__x86_indirect_thunk_rax" },
	{ 0xe8213e80, "_printk" },
	{ 0xbd03ed67, "__ref_stack_chk_guard" },
	{ 0xd272d446, "schedule" },
	{ 0x6ac784f4, "schedule_timeout" },
	{ 0x2e93fc50, "__tracepoint_sched_set_state_tp" },
	{ 0xd272d446, "__stack_chk_fail" },
	{ 0x5af09d8b, "_raw_spin_unlock_bh" },
	{ 0x8e5a9bc9, "usb_kill_anchored_urbs" },
	{ 0x9479a1e8, "strnlen" },
	{ 0x5a844b26, "__x86_indirect_thunk_rdx" },
	{ 0x073389b3, "usb_submit_urb" },
	{ 0x86d206f6, "__SCT__WARN_trap" },
	{ 0x90a48d82, "__ubsan_handle_out_of_bounds" },
	{ 0x7a5ffe84, "init_wait_entry" },
	{ 0x381595f9, "skb_pull" },
	{ 0xaef1f20d, "system_percpu_wq" },
	{ 0xbd03ed67, "random_kmalloc_seed" },
	{ 0xd7a59a65, "vmalloc_noprof" },
	{ 0xa04d7f97, "const_current_task" },
	{ 0x5a844b26, "__x86_indirect_thunk_r13" },
	{ 0x3d395066, "wait_for_completion_interruptible" },
	{ 0x4f1e5fd0, "__list_del_entry_valid_or_report" },
	{ 0x0b12d1b3, "kthread_stop" },
	{ 0x48bb2c0c, "usb_deregister" },
	{ 0xe54e0a6b, "__fortify_panic" },
	{ 0x444885a7, "_raw_spin_unlock_irqrestore" },
	{ 0x0e9cab28, "memset" },
	{ 0x6a71b8cf, "kernel_read" },
	{ 0x6881db1b, "skb_dequeue_tail" },
	{ 0xd272d446, "__x86_return_thunk" },
	{ 0xe804603d, "__init_waitqueue_head" },
	{ 0xe2f0b42b, "__netdev_alloc_skb" },
	{ 0x62cbec20, "complete_all" },
	{ 0x403d6ea6, "usb_unanchor_urb" },
	{ 0xb22d80ed, "param_ops_string" },
	{ 0x888b8f57, "strcmp" },
	{ 0x3e2b9230, "skb_unlink" },
	{ 0xb8d8e3ca, "kthread_create_on_node" },
	{ 0xdd6830c7, "sprintf" },
	{ 0x7ec472ba, "__preempt_count" },
	{ 0xf1de9e85, "vfree" },
	{ 0xcbae5412, "__const_udelay" },
	{ 0xf745e777, "wait_for_completion_killable_timeout" },
	{ 0xeb253419, "filp_close" },
	{ 0x2f9595d1, "__kmalloc_cache_noprof" },
	{ 0x403d6ea6, "usb_kill_urb" },
	{ 0x2d88a3ab, "cancel_work_sync" },
	{ 0x5a844b26, "__x86_indirect_thunk_r9" },
	{ 0x5af09d8b, "_raw_spin_lock_bh" },
	{ 0x97d05605, "send_sig" },
	{ 0xe4de56b4, "__ubsan_handle_load_invalid_value" },
	{ 0x43a349ca, "strlen" },
	{ 0xca602bb3, "dev_kfree_skb_any_reason" },
	{ 0xb22d80ed, "param_ops_int" },
	{ 0x5af09d8b, "_raw_spin_unlock" },
	{ 0x67628f51, "msleep" },
	{ 0x7851be11, "__SCT__might_resched" },
	{ 0x4944b104, "kmalloc_caches" },
	{ 0xb2e62cba, "__trace_set_current_state" },
	{ 0x9e18d759, "filp_open" },
	{ 0xf279c893, "usb_alloc_urb" },
	{ 0x456a1c62, "usb_anchor_urb" },
	{ 0xdc352a3b, "__list_add_valid_or_report" },
	{ 0x403d6ea6, "usb_free_urb" },
	{ 0x381595f9, "skb_put" },
	{ 0x534ed5f3, "__msecs_to_jiffies" },
	{ 0xd710adbf, "__kmalloc_noprof" },
	{ 0x4d74d15a, "consume_skb" },
	{ 0x40a621c5, "snprintf" },
	{ 0x62cbec20, "complete" },
	{ 0x49733ad6, "queue_work_on" },
	{ 0xc2ccdd1e, "__init_swait_queue_head" },
	{ 0xb730487b, "finish_wait" },
	{ 0xe63769e7, "module_layout" },
};

static const u32 ____version_ext_crcs[]
__used __section("__version_ext_crcs") = {
	0xcbf03397,
	0xb2fa43dd,
	0xfbe7861b,
	0xcb8b6ec6,
	0xc281f1fb,
	0x5e505530,
	0x68a1b6c6,
	0x11f4259a,
	0x5af09d8b,
	0xd272d446,
	0x4f51989c,
	0x5a844b26,
	0xe8213e80,
	0xbd03ed67,
	0xd272d446,
	0x6ac784f4,
	0x2e93fc50,
	0xd272d446,
	0x5af09d8b,
	0x8e5a9bc9,
	0x9479a1e8,
	0x5a844b26,
	0x073389b3,
	0x86d206f6,
	0x90a48d82,
	0x7a5ffe84,
	0x381595f9,
	0xaef1f20d,
	0xbd03ed67,
	0xd7a59a65,
	0xa04d7f97,
	0x5a844b26,
	0x3d395066,
	0x4f1e5fd0,
	0x0b12d1b3,
	0x48bb2c0c,
	0xe54e0a6b,
	0x444885a7,
	0x0e9cab28,
	0x6a71b8cf,
	0x6881db1b,
	0xd272d446,
	0xe804603d,
	0xe2f0b42b,
	0x62cbec20,
	0x403d6ea6,
	0xb22d80ed,
	0x888b8f57,
	0x3e2b9230,
	0xb8d8e3ca,
	0xdd6830c7,
	0x7ec472ba,
	0xf1de9e85,
	0xcbae5412,
	0xf745e777,
	0xeb253419,
	0x2f9595d1,
	0x403d6ea6,
	0x2d88a3ab,
	0x5a844b26,
	0x5af09d8b,
	0x97d05605,
	0xe4de56b4,
	0x43a349ca,
	0xca602bb3,
	0xb22d80ed,
	0x5af09d8b,
	0x67628f51,
	0x7851be11,
	0x4944b104,
	0xb2e62cba,
	0x9e18d759,
	0xf279c893,
	0x456a1c62,
	0xdc352a3b,
	0x403d6ea6,
	0x381595f9,
	0x534ed5f3,
	0xd710adbf,
	0x4d74d15a,
	0x40a621c5,
	0x62cbec20,
	0x49733ad6,
	0xc2ccdd1e,
	0xb730487b,
	0xe63769e7,
};
static const char ____version_ext_names[]
__used __section("__version_ext_names") =
	"usb_register_driver\0"
	"kernel_sigaction\0"
	"memcpy\0"
	"kfree\0"
	"prepare_to_wait_event\0"
	"kthread_should_stop\0"
	"__wake_up\0"
	"_raw_spin_lock_irqsave\0"
	"_raw_spin_lock\0"
	"__fentry__\0"
	"wake_up_process\0"
	"__x86_indirect_thunk_rax\0"
	"_printk\0"
	"__ref_stack_chk_guard\0"
	"schedule\0"
	"schedule_timeout\0"
	"__tracepoint_sched_set_state_tp\0"
	"__stack_chk_fail\0"
	"_raw_spin_unlock_bh\0"
	"usb_kill_anchored_urbs\0"
	"strnlen\0"
	"__x86_indirect_thunk_rdx\0"
	"usb_submit_urb\0"
	"__SCT__WARN_trap\0"
	"__ubsan_handle_out_of_bounds\0"
	"init_wait_entry\0"
	"skb_pull\0"
	"system_percpu_wq\0"
	"random_kmalloc_seed\0"
	"vmalloc_noprof\0"
	"const_current_task\0"
	"__x86_indirect_thunk_r13\0"
	"wait_for_completion_interruptible\0"
	"__list_del_entry_valid_or_report\0"
	"kthread_stop\0"
	"usb_deregister\0"
	"__fortify_panic\0"
	"_raw_spin_unlock_irqrestore\0"
	"memset\0"
	"kernel_read\0"
	"skb_dequeue_tail\0"
	"__x86_return_thunk\0"
	"__init_waitqueue_head\0"
	"__netdev_alloc_skb\0"
	"complete_all\0"
	"usb_unanchor_urb\0"
	"param_ops_string\0"
	"strcmp\0"
	"skb_unlink\0"
	"kthread_create_on_node\0"
	"sprintf\0"
	"__preempt_count\0"
	"vfree\0"
	"__const_udelay\0"
	"wait_for_completion_killable_timeout\0"
	"filp_close\0"
	"__kmalloc_cache_noprof\0"
	"usb_kill_urb\0"
	"cancel_work_sync\0"
	"__x86_indirect_thunk_r9\0"
	"_raw_spin_lock_bh\0"
	"send_sig\0"
	"__ubsan_handle_load_invalid_value\0"
	"strlen\0"
	"dev_kfree_skb_any_reason\0"
	"param_ops_int\0"
	"_raw_spin_unlock\0"
	"msleep\0"
	"__SCT__might_resched\0"
	"kmalloc_caches\0"
	"__trace_set_current_state\0"
	"filp_open\0"
	"usb_alloc_urb\0"
	"usb_anchor_urb\0"
	"__list_add_valid_or_report\0"
	"usb_free_urb\0"
	"skb_put\0"
	"__msecs_to_jiffies\0"
	"__kmalloc_noprof\0"
	"consume_skb\0"
	"snprintf\0"
	"complete\0"
	"queue_work_on\0"
	"__init_swait_queue_head\0"
	"finish_wait\0"
	"module_layout\0"
;

MODULE_INFO(depends, "");

MODULE_ALIAS("usb:vA69Cp8800d*dc*dsc*dp*ic*isc*ip*in*");
MODULE_ALIAS("usb:vA69Cp8801d*dc*dsc*dp*ic*isc*ip*in*");
MODULE_ALIAS("usb:vA69Cp8D80d*dc*dsc*dp*ic*isc*ip*in*");
MODULE_ALIAS("usb:vA69Cp8D81d*dc*dsc*dp*ic*isc*ip*in*");
MODULE_ALIAS("usb:vA69Cp8D40d*dc*dsc*dp*ic*isc*ip*in*");
MODULE_ALIAS("usb:vA69Cp8D41d*dc*dsc*dp*ic*isc*ip*in*");
MODULE_ALIAS("usb:v368Bp8D90d*dc*dsc*dp*ic*isc*ip*in*");
MODULE_ALIAS("usb:v368Bp8D91d*dc*dsc*dp*ic*isc*ip*in*");
MODULE_ALIAS("usb:v368Bp8D99d*dc*dsc*dp*ic*isc*ip*in*");
MODULE_ALIAS("usb:v368Bp8D92d*dc*dsc*dp*ic*isc*ip*in*");

MODULE_INFO(srcversion, "6741AB62FF8B9C4FC5DD14F");
