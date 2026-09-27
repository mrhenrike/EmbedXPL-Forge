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



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xffaf0bb7, "ieee80211_get_channel_khz" },
	{ 0x90a48d82, "__ubsan_handle_out_of_bounds" },
	{ 0xbd03ed67, "page_offset_base" },
	{ 0x0c51d4e0, "__cfg80211_radar_event" },
	{ 0x7851be11, "get_testmode" },
	{ 0x26226372, "cfg80211_find_elem_match" },
	{ 0x5c9888a2, "tasklet_kill" },
	{ 0x23ce2114, "pci_clear_master" },
	{ 0x6a8903ed, "__pm_relax" },
	{ 0x7a5ffe84, "init_wait_entry" },
	{ 0xa92a5114, "pci_enable_msi" },
	{ 0x11e98b2f, "_dev_err" },
	{ 0x07bc7e7e, "sort" },
	{ 0xc5440793, "simple_open" },
	{ 0x381595f9, "skb_pull" },
	{ 0xcd76fbf8, "cpu_bit_bitmap" },
	{ 0x9126ce86, "request_threaded_irq" },
	{ 0x6a8903ed, "wakeup_source_unregister" },
	{ 0xd272d446, "__rcu_read_unlock" },
	{ 0xd16c30e1, "sk_skb_reason_drop" },
	{ 0xaef1f20d, "system_percpu_wq" },
	{ 0x32feeafc, "mod_timer" },
	{ 0x38a4f384, "tasklet_init" },
	{ 0x7851be11, "get_flash_bin_size" },
	{ 0xd5c3f38c, "down" },
	{ 0xbd03ed67, "random_kmalloc_seed" },
	{ 0xd7a59a65, "vmalloc_noprof" },
	{ 0xd872b378, "cfg80211_michael_mic_failure" },
	{ 0xe71db9f4, "cfg80211_cqm_pktloss_notify" },
	{ 0xbeb1d261, "destroy_workqueue" },
	{ 0x9aa6980d, "mutex_lock" },
	{ 0x381595f9, "skb_push" },
	{ 0x49caf705, "kmem_cache_free" },
	{ 0x32cdd706, "set_cpus_allowed_ptr" },
	{ 0x55b20920, "debugfs_remove" },
	{ 0x5f2687e1, "pci_read_config_word" },
	{ 0x2435d559, "strncmp" },
	{ 0x66df15f6, "cfg80211_del_sta_sinfo" },
	{ 0x04cfe226, "netif_receive_skb" },
	{ 0xfb5f8ff5, "nla_put" },
	{ 0xa04d7f97, "const_current_task" },
	{ 0xc609ff70, "strncpy" },
	{ 0x5c9888a2, "__tasklet_schedule" },
	{ 0xd3ed45de, "strcasecmp" },
	{ 0x5a844b26, "__x86_indirect_thunk_r13" },
	{ 0x290293dd, "wiphy_unregister" },
	{ 0x865363a2, "free_netdev" },
	{ 0x3d395066, "wait_for_completion_interruptible" },
	{ 0xc01aafd2, "get_flash_bin_crc" },
	{ 0xbd03ed67, "phys_base" },
	{ 0x4f1e5fd0, "__list_del_entry_valid_or_report" },
	{ 0xe8986db8, "cfg80211_notify_new_peer_candidate" },
	{ 0x402db74e, "memcmp" },
	{ 0xfcc2e8f3, "__local_bh_enable_ip" },
	{ 0x0b12d1b3, "kthread_stop" },
	{ 0x173ec8da, "sscanf" },
	{ 0x48bb2c0c, "usb_deregister" },
	{ 0xe54e0a6b, "__fortify_panic" },
	{ 0x444885a7, "_raw_spin_unlock_irqrestore" },
	{ 0x9b4b48a0, "_ctype" },
	{ 0x865363a2, "netif_tx_stop_all_queues" },
	{ 0x8c74d144, "netif_tx_wake_queue" },
	{ 0x85acaba2, "cancel_delayed_work" },
	{ 0xb311a158, "ns_to_timespec64" },
	{ 0x7295b8c3, "ieee80211_freq_khz_to_channel" },
	{ 0x0e9cab28, "memset" },
	{ 0x39cdbfa0, "cfg80211_vendor_cmd_reply" },
	{ 0xfb44bbd0, "aicwf_prealloc_txq_alloc" },
	{ 0x23ce2114, "pci_set_master" },
	{ 0x6a71b8cf, "kernel_read" },
	{ 0xb22d80ed, "param_ops_charp" },
	{ 0x6881db1b, "skb_dequeue_tail" },
	{ 0xbeb1d261, "__flush_workqueue" },
	{ 0xd272d446, "__x86_return_thunk" },
	{ 0x356fc1fc, "debugfs_create_u32" },
	{ 0x7d45d049, "kmem_cache_alloc_noprof" },
	{ 0xb88570d6, "iwe_stream_add_point" },
	{ 0x96cce25e, "cfg80211_stop_link" },
	{ 0x092a35a2, "_copy_to_user" },
	{ 0xe804603d, "__init_waitqueue_head" },
	{ 0xe2f0b42b, "__netdev_alloc_skb" },
	{ 0x62cbec20, "complete_all" },
	{ 0x403d6ea6, "usb_unanchor_urb" },
	{ 0xc1c340fa, "__kmem_cache_create_args" },
	{ 0x40c76f23, "set_testmode" },
	{ 0x11fd4e2a, "aicwf_prealloc_rxbuff_alloc" },
	{ 0xb22d80ed, "param_ops_string" },
	{ 0x888b8f57, "strcmp" },
	{ 0xbb694647, "cfg80211_ch_switch_started_notify" },
	{ 0x3e2b9230, "skb_unlink" },
	{ 0x860eeb81, "__dynamic_netdev_dbg" },
	{ 0x058c185a, "jiffies" },
	{ 0xb8d8e3ca, "kthread_create_on_node" },
	{ 0x7a6661ca, "ktime_get_real_seconds" },
	{ 0xdd6830c7, "sprintf" },
	{ 0xbd03ed67, "vmemmap_base" },
	{ 0x82fd7238, "__ubsan_handle_shift_out_of_bounds" },
	{ 0x7ec472ba, "__preempt_count" },
	{ 0xf30bacfb, "cfg80211_unregister_wdev" },
	{ 0xd2eb164a, "__dev_queue_xmit" },
	{ 0x8abae305, "cfg80211_probe_status" },
	{ 0xf1de9e85, "vfree" },
	{ 0x0bb95b37, "cfg80211_rx_mgmt_ext" },
	{ 0x9aa6980d, "mutex_unlock" },
	{ 0xb22d80ed, "param_ops_bool" },
	{ 0x7abff8bc, "pci_release_regions" },
	{ 0xeacf5681, "__dma_sync_single_for_device" },
	{ 0xcbae5412, "__const_udelay" },
	{ 0xf745e777, "wait_for_completion_killable_timeout" },
	{ 0x31386fa7, "pci_write_config_byte" },
	{ 0xeb253419, "filp_close" },
	{ 0x2f9595d1, "__kmalloc_cache_noprof" },
	{ 0x403d6ea6, "usb_kill_urb" },
	{ 0x97acb853, "ktime_get" },
	{ 0x2d88a3ab, "cancel_work_sync" },
	{ 0x5cb46e6d, "validate_usercopy_range" },
	{ 0xfff9f928, "netif_carrier_off" },
	{ 0x5a844b26, "__x86_indirect_thunk_r9" },
	{ 0x71798f7e, "delayed_work_timer_fn" },
	{ 0x7fd36f2e, "time64_to_tm" },
	{ 0x5af09d8b, "_raw_spin_lock_bh" },
	{ 0xfff9f928, "netif_carrier_on" },
	{ 0xcbcbbfe0, "aicwf_prealloc_rxbuff_free" },
	{ 0xbde737b4, "debugfs_create_file_full" },
	{ 0xfd6ceec4, "cfg80211_chandef_create" },
	{ 0xd272d446, "rtnl_lock" },
	{ 0xf20d7a48, "cfg80211_ft_event" },
	{ 0x23ce2114, "pci_disable_device" },
	{ 0x586d1f60, "get_userconfig_txpwr_ofst" },
	{ 0x02f9bbf0, "timer_init_key" },
	{ 0x224a53e7, "get_random_bytes" },
	{ 0x6a8903ed, "__pm_stay_awake" },
	{ 0x5a844b26, "__x86_indirect_thunk_r12" },
	{ 0x36b10afd, "cfg80211_inform_bss_data" },
	{ 0x8e3336dd, "disable_irq_nosync" },
	{ 0xdf4bee3d, "alloc_workqueue_noprof" },
	{ 0xe4de56b4, "__ubsan_handle_load_invalid_value" },
	{ 0x43a349ca, "strlen" },
	{ 0xca602bb3, "dev_kfree_skb_any_reason" },
	{ 0x5247e89a, "cfg80211_report_obss_beacon_khz" },
	{ 0xe2ef1e54, "regulatory_set_wiphy_regd" },
	{ 0xb22d80ed, "param_ops_int" },
	{ 0xebb4e286, "skb_append" },
	{ 0x4f11b9b4, "debugfs_create_dir" },
	{ 0xd6470c7d, "pci_write_config_word" },
	{ 0x0e95ec6a, "get_fw_path" },
	{ 0x6711edca, "generic_file_llseek" },
	{ 0x5af09d8b, "_raw_spin_unlock" },
	{ 0x437e81c7, "simple_read_from_buffer" },
	{ 0x1429f820, "cfg80211_connect_done" },
	{ 0x2214e767, "cfg80211_unlink_bss" },
	{ 0x3830ec4d, "__cfg80211_get_bss" },
	{ 0x290293dd, "wiphy_free" },
	{ 0x67628f51, "msleep" },
	{ 0x12ca6142, "ktime_get_with_offset" },
	{ 0xf8514a94, "cfg80211_cqm_rssi_notify" },
	{ 0x7851be11, "__SCT__might_resched" },
	{ 0x4944b104, "kmalloc_caches" },
	{ 0xb2e62cba, "__trace_set_current_state" },
	{ 0x1b60b418, "netdev_info" },
	{ 0x1220bd99, "kmem_cache_destroy" },
	{ 0x9aa6980d, "mutex_init_generic" },
	{ 0x322df114, "skb_queue_head" },
	{ 0x2d88a3ab, "flush_work" },
	{ 0x4c850387, "cfg80211_rx_unprot_mlme_mgmt" },
	{ 0x9e18d759, "filp_open" },
	{ 0x9dd4105e, "free_irq" },
	{ 0xc45d298e, "is_vmalloc_addr" },
	{ 0xf279c893, "usb_alloc_urb" },
	{ 0xf8b67b25, "cfg80211_mgmt_tx_status_ext" },
	{ 0xe2ef1e54, "regulatory_set_wiphy_regd_sync" },
	{ 0x25910ff5, "cfg80211_rx_unexpected_4addr_frame" },
	{ 0x456a1c62, "usb_anchor_urb" },
	{ 0xa61fd7aa, "__check_object_size" },
	{ 0xd272d446, "rtnl_unlock" },
	{ 0x45cc0f4a, "wakeup_source_register" },
	{ 0x1abc7887, "release_firmware" },
	{ 0x89faa916, "down_timeout" },
	{ 0xdc352a3b, "__list_add_valid_or_report" },
	{ 0x403d6ea6, "usb_free_urb" },
	{ 0x092a35a2, "_copy_from_user" },
	{ 0x474d7bd8, "eth_mac_addr" },
	{ 0x60f855e0, "pci_enable_device" },
	{ 0x381595f9, "skb_put" },
	{ 0xd272d446, "__rcu_read_lock" },
	{ 0x1e9c2610, "iwe_stream_add_event" },
	{ 0x4d32a58a, "cfg80211_scan_done" },
	{ 0x534ed5f3, "__msecs_to_jiffies" },
	{ 0xd710adbf, "__kmalloc_noprof" },
	{ 0x4d74d15a, "consume_skb" },
	{ 0xfbe7861b, "memmove" },
	{ 0x7851be11, "get_adap_test" },
	{ 0x40a621c5, "snprintf" },
	{ 0x62cbec20, "complete" },
	{ 0x49733ad6, "queue_work_on" },
	{ 0xaa284761, "cfg80211_remain_on_channel_expired" },
	{ 0x1a336f8e, "cfg80211_cac_event" },
	{ 0x6881db1b, "skb_dequeue" },
	{ 0xc2ccdd1e, "__init_swait_queue_head" },
	{ 0xb730487b, "finish_wait" },
	{ 0xae51d993, "cfg80211_register_netdevice" },
	{ 0xa836deb4, "dma_unmap_page_attrs" },
	{ 0xc36345fa, "__sw_hweight32" },
	{ 0xbc5d2f7e, "request_firmware" },
	{ 0xcbf03397, "usb_register_driver" },
	{ 0x40a621c5, "scnprintf" },
	{ 0xfff3e370, "__pci_register_driver" },
	{ 0xd5c3f38c, "up" },
	{ 0x12ad300e, "iounmap" },
	{ 0x7851be11, "aicwf_rxbuff_size_get" },
	{ 0xeca569af, "ieee80211_chandef_to_operating_class" },
	{ 0xdf1c4a30, "pci_disable_msi" },
	{ 0x8b48eb5b, "pci_request_regions" },
	{ 0xfbe7861b, "memcpy" },
	{ 0x10bd5ed5, "regulatory_hint" },
	{ 0xcb8b6ec6, "kfree" },
	{ 0x1935f78b, "__trace_bprintk" },
	{ 0x2352b148, "timer_delete" },
	{ 0x5262df42, "get_userconfig_txpwr_idx" },
	{ 0x557f246e, "cfg80211_external_auth_request" },
	{ 0xc281f1fb, "prepare_to_wait_event" },
	{ 0x1b60b418, "netdev_warn" },
	{ 0x5e505530, "kthread_should_stop" },
	{ 0x2352b148, "timer_delete_sync" },
	{ 0x68a1b6c6, "__wake_up" },
	{ 0x66df15f6, "cfg80211_new_sta" },
	{ 0x11f4259a, "_raw_spin_lock_irqsave" },
	{ 0x6c857694, "pci_ioremap_bar" },
	{ 0x840f161f, "sched_set_fifo_low" },
	{ 0xb96275a8, "cfg80211_disconnected" },
	{ 0x9db0dd3f, "ether_setup" },
	{ 0xa01ec9a8, "pci_unregister_driver" },
	{ 0x1b60b418, "netdev_err" },
	{ 0xd272d446, "__fentry__" },
	{ 0x4f51989c, "wake_up_process" },
	{ 0xa4912d65, "dev_driver_string" },
	{ 0xfb577918, "dev_addr_mod" },
	{ 0x79c6df2d, "eth_type_trans" },
	{ 0x5a844b26, "__x86_indirect_thunk_rax" },
	{ 0x9c79766f, "dma_map_page_attrs" },
	{ 0x334383d3, "pm_wakeup_ws_event" },
	{ 0xd9368fef, "alloc_netdev_mqs" },
	{ 0x4f673be2, "wiphy_new_nm" },
	{ 0xd272d446, "dump_stack" },
	{ 0xe8213e80, "_printk" },
	{ 0xd3901426, "cfg80211_ready_on_channel" },
	{ 0x5629a063, "strncasecmp" },
	{ 0xbd03ed67, "__ref_stack_chk_guard" },
	{ 0xd272d446, "schedule" },
	{ 0x6ac784f4, "schedule_timeout" },
	{ 0xf51910ad, "cfg80211_classify8021d" },
	{ 0x2e93fc50, "__tracepoint_sched_set_state_tp" },
	{ 0xd272d446, "__stack_chk_fail" },
	{ 0x8ce83585, "queue_delayed_work_on" },
	{ 0x5af09d8b, "_raw_spin_unlock_bh" },
	{ 0xd710adbf, "__kmalloc_large_noprof" },
	{ 0x1c57b7f8, "wiphy_register" },
	{ 0x48c02361, "__cfg80211_alloc_reply_skb" },
	{ 0xf64ac983, "__copy_overflow" },
	{ 0x8e5a9bc9, "usb_kill_anchored_urbs" },
	{ 0x9479a1e8, "strnlen" },
	{ 0x2214e767, "cfg80211_put_bss" },
	{ 0x865363a2, "netif_device_detach" },
	{ 0x3054e769, "cfg80211_roamed" },
	{ 0x7408774f, "cfg80211_ch_switch_notify" },
	{ 0x5a844b26, "__x86_indirect_thunk_rdx" },
	{ 0x073389b3, "usb_submit_urb" },
	{ 0x86d206f6, "__SCT__WARN_trap" },
	{ 0x865363a2, "netif_device_attach" },
	{ 0xb628b549, "skb_copy_expand" },
	{ 0x322df114, "skb_queue_tail" },
	{ 0x61079369, "print_hex_dump" },
	{ 0xe63769e7, "module_layout" },
};

static const u32 ____version_ext_crcs[]
__used __section("__version_ext_crcs") = {
	0xffaf0bb7,
	0x90a48d82,
	0xbd03ed67,
	0x0c51d4e0,
	0x7851be11,
	0x26226372,
	0x5c9888a2,
	0x23ce2114,
	0x6a8903ed,
	0x7a5ffe84,
	0xa92a5114,
	0x11e98b2f,
	0x07bc7e7e,
	0xc5440793,
	0x381595f9,
	0xcd76fbf8,
	0x9126ce86,
	0x6a8903ed,
	0xd272d446,
	0xd16c30e1,
	0xaef1f20d,
	0x32feeafc,
	0x38a4f384,
	0x7851be11,
	0xd5c3f38c,
	0xbd03ed67,
	0xd7a59a65,
	0xd872b378,
	0xe71db9f4,
	0xbeb1d261,
	0x9aa6980d,
	0x381595f9,
	0x49caf705,
	0x32cdd706,
	0x55b20920,
	0x5f2687e1,
	0x2435d559,
	0x66df15f6,
	0x04cfe226,
	0xfb5f8ff5,
	0xa04d7f97,
	0xc609ff70,
	0x5c9888a2,
	0xd3ed45de,
	0x5a844b26,
	0x290293dd,
	0x865363a2,
	0x3d395066,
	0xc01aafd2,
	0xbd03ed67,
	0x4f1e5fd0,
	0xe8986db8,
	0x402db74e,
	0xfcc2e8f3,
	0x0b12d1b3,
	0x173ec8da,
	0x48bb2c0c,
	0xe54e0a6b,
	0x444885a7,
	0x9b4b48a0,
	0x865363a2,
	0x8c74d144,
	0x85acaba2,
	0xb311a158,
	0x7295b8c3,
	0x0e9cab28,
	0x39cdbfa0,
	0xfb44bbd0,
	0x23ce2114,
	0x6a71b8cf,
	0xb22d80ed,
	0x6881db1b,
	0xbeb1d261,
	0xd272d446,
	0x356fc1fc,
	0x7d45d049,
	0xb88570d6,
	0x96cce25e,
	0x092a35a2,
	0xe804603d,
	0xe2f0b42b,
	0x62cbec20,
	0x403d6ea6,
	0xc1c340fa,
	0x40c76f23,
	0x11fd4e2a,
	0xb22d80ed,
	0x888b8f57,
	0xbb694647,
	0x3e2b9230,
	0x860eeb81,
	0x058c185a,
	0xb8d8e3ca,
	0x7a6661ca,
	0xdd6830c7,
	0xbd03ed67,
	0x82fd7238,
	0x7ec472ba,
	0xf30bacfb,
	0xd2eb164a,
	0x8abae305,
	0xf1de9e85,
	0x0bb95b37,
	0x9aa6980d,
	0xb22d80ed,
	0x7abff8bc,
	0xeacf5681,
	0xcbae5412,
	0xf745e777,
	0x31386fa7,
	0xeb253419,
	0x2f9595d1,
	0x403d6ea6,
	0x97acb853,
	0x2d88a3ab,
	0x5cb46e6d,
	0xfff9f928,
	0x5a844b26,
	0x71798f7e,
	0x7fd36f2e,
	0x5af09d8b,
	0xfff9f928,
	0xcbcbbfe0,
	0xbde737b4,
	0xfd6ceec4,
	0xd272d446,
	0xf20d7a48,
	0x23ce2114,
	0x586d1f60,
	0x02f9bbf0,
	0x224a53e7,
	0x6a8903ed,
	0x5a844b26,
	0x36b10afd,
	0x8e3336dd,
	0xdf4bee3d,
	0xe4de56b4,
	0x43a349ca,
	0xca602bb3,
	0x5247e89a,
	0xe2ef1e54,
	0xb22d80ed,
	0xebb4e286,
	0x4f11b9b4,
	0xd6470c7d,
	0x0e95ec6a,
	0x6711edca,
	0x5af09d8b,
	0x437e81c7,
	0x1429f820,
	0x2214e767,
	0x3830ec4d,
	0x290293dd,
	0x67628f51,
	0x12ca6142,
	0xf8514a94,
	0x7851be11,
	0x4944b104,
	0xb2e62cba,
	0x1b60b418,
	0x1220bd99,
	0x9aa6980d,
	0x322df114,
	0x2d88a3ab,
	0x4c850387,
	0x9e18d759,
	0x9dd4105e,
	0xc45d298e,
	0xf279c893,
	0xf8b67b25,
	0xe2ef1e54,
	0x25910ff5,
	0x456a1c62,
	0xa61fd7aa,
	0xd272d446,
	0x45cc0f4a,
	0x1abc7887,
	0x89faa916,
	0xdc352a3b,
	0x403d6ea6,
	0x092a35a2,
	0x474d7bd8,
	0x60f855e0,
	0x381595f9,
	0xd272d446,
	0x1e9c2610,
	0x4d32a58a,
	0x534ed5f3,
	0xd710adbf,
	0x4d74d15a,
	0xfbe7861b,
	0x7851be11,
	0x40a621c5,
	0x62cbec20,
	0x49733ad6,
	0xaa284761,
	0x1a336f8e,
	0x6881db1b,
	0xc2ccdd1e,
	0xb730487b,
	0xae51d993,
	0xa836deb4,
	0xc36345fa,
	0xbc5d2f7e,
	0xcbf03397,
	0x40a621c5,
	0xfff3e370,
	0xd5c3f38c,
	0x12ad300e,
	0x7851be11,
	0xeca569af,
	0xdf1c4a30,
	0x8b48eb5b,
	0xfbe7861b,
	0x10bd5ed5,
	0xcb8b6ec6,
	0x1935f78b,
	0x2352b148,
	0x5262df42,
	0x557f246e,
	0xc281f1fb,
	0x1b60b418,
	0x5e505530,
	0x2352b148,
	0x68a1b6c6,
	0x66df15f6,
	0x11f4259a,
	0x6c857694,
	0x840f161f,
	0xb96275a8,
	0x9db0dd3f,
	0xa01ec9a8,
	0x1b60b418,
	0xd272d446,
	0x4f51989c,
	0xa4912d65,
	0xfb577918,
	0x79c6df2d,
	0x5a844b26,
	0x9c79766f,
	0x334383d3,
	0xd9368fef,
	0x4f673be2,
	0xd272d446,
	0xe8213e80,
	0xd3901426,
	0x5629a063,
	0xbd03ed67,
	0xd272d446,
	0x6ac784f4,
	0xf51910ad,
	0x2e93fc50,
	0xd272d446,
	0x8ce83585,
	0x5af09d8b,
	0xd710adbf,
	0x1c57b7f8,
	0x48c02361,
	0xf64ac983,
	0x8e5a9bc9,
	0x9479a1e8,
	0x2214e767,
	0x865363a2,
	0x3054e769,
	0x7408774f,
	0x5a844b26,
	0x073389b3,
	0x86d206f6,
	0x865363a2,
	0xb628b549,
	0x322df114,
	0x61079369,
	0xe63769e7,
};
static const char ____version_ext_names[]
__used __section("__version_ext_names") =
	"ieee80211_get_channel_khz\0"
	"__ubsan_handle_out_of_bounds\0"
	"page_offset_base\0"
	"__cfg80211_radar_event\0"
	"get_testmode\0"
	"cfg80211_find_elem_match\0"
	"tasklet_kill\0"
	"pci_clear_master\0"
	"__pm_relax\0"
	"init_wait_entry\0"
	"pci_enable_msi\0"
	"_dev_err\0"
	"sort\0"
	"simple_open\0"
	"skb_pull\0"
	"cpu_bit_bitmap\0"
	"request_threaded_irq\0"
	"wakeup_source_unregister\0"
	"__rcu_read_unlock\0"
	"sk_skb_reason_drop\0"
	"system_percpu_wq\0"
	"mod_timer\0"
	"tasklet_init\0"
	"get_flash_bin_size\0"
	"down\0"
	"random_kmalloc_seed\0"
	"vmalloc_noprof\0"
	"cfg80211_michael_mic_failure\0"
	"cfg80211_cqm_pktloss_notify\0"
	"destroy_workqueue\0"
	"mutex_lock\0"
	"skb_push\0"
	"kmem_cache_free\0"
	"set_cpus_allowed_ptr\0"
	"debugfs_remove\0"
	"pci_read_config_word\0"
	"strncmp\0"
	"cfg80211_del_sta_sinfo\0"
	"netif_receive_skb\0"
	"nla_put\0"
	"const_current_task\0"
	"strncpy\0"
	"__tasklet_schedule\0"
	"strcasecmp\0"
	"__x86_indirect_thunk_r13\0"
	"wiphy_unregister\0"
	"free_netdev\0"
	"wait_for_completion_interruptible\0"
	"get_flash_bin_crc\0"
	"phys_base\0"
	"__list_del_entry_valid_or_report\0"
	"cfg80211_notify_new_peer_candidate\0"
	"memcmp\0"
	"__local_bh_enable_ip\0"
	"kthread_stop\0"
	"sscanf\0"
	"usb_deregister\0"
	"__fortify_panic\0"
	"_raw_spin_unlock_irqrestore\0"
	"_ctype\0"
	"netif_tx_stop_all_queues\0"
	"netif_tx_wake_queue\0"
	"cancel_delayed_work\0"
	"ns_to_timespec64\0"
	"ieee80211_freq_khz_to_channel\0"
	"memset\0"
	"cfg80211_vendor_cmd_reply\0"
	"aicwf_prealloc_txq_alloc\0"
	"pci_set_master\0"
	"kernel_read\0"
	"param_ops_charp\0"
	"skb_dequeue_tail\0"
	"__flush_workqueue\0"
	"__x86_return_thunk\0"
	"debugfs_create_u32\0"
	"kmem_cache_alloc_noprof\0"
	"iwe_stream_add_point\0"
	"cfg80211_stop_link\0"
	"_copy_to_user\0"
	"__init_waitqueue_head\0"
	"__netdev_alloc_skb\0"
	"complete_all\0"
	"usb_unanchor_urb\0"
	"__kmem_cache_create_args\0"
	"set_testmode\0"
	"aicwf_prealloc_rxbuff_alloc\0"
	"param_ops_string\0"
	"strcmp\0"
	"cfg80211_ch_switch_started_notify\0"
	"skb_unlink\0"
	"__dynamic_netdev_dbg\0"
	"jiffies\0"
	"kthread_create_on_node\0"
	"ktime_get_real_seconds\0"
	"sprintf\0"
	"vmemmap_base\0"
	"__ubsan_handle_shift_out_of_bounds\0"
	"__preempt_count\0"
	"cfg80211_unregister_wdev\0"
	"__dev_queue_xmit\0"
	"cfg80211_probe_status\0"
	"vfree\0"
	"cfg80211_rx_mgmt_ext\0"
	"mutex_unlock\0"
	"param_ops_bool\0"
	"pci_release_regions\0"
	"__dma_sync_single_for_device\0"
	"__const_udelay\0"
	"wait_for_completion_killable_timeout\0"
	"pci_write_config_byte\0"
	"filp_close\0"
	"__kmalloc_cache_noprof\0"
	"usb_kill_urb\0"
	"ktime_get\0"
	"cancel_work_sync\0"
	"validate_usercopy_range\0"
	"netif_carrier_off\0"
	"__x86_indirect_thunk_r9\0"
	"delayed_work_timer_fn\0"
	"time64_to_tm\0"
	"_raw_spin_lock_bh\0"
	"netif_carrier_on\0"
	"aicwf_prealloc_rxbuff_free\0"
	"debugfs_create_file_full\0"
	"cfg80211_chandef_create\0"
	"rtnl_lock\0"
	"cfg80211_ft_event\0"
	"pci_disable_device\0"
	"get_userconfig_txpwr_ofst\0"
	"timer_init_key\0"
	"get_random_bytes\0"
	"__pm_stay_awake\0"
	"__x86_indirect_thunk_r12\0"
	"cfg80211_inform_bss_data\0"
	"disable_irq_nosync\0"
	"alloc_workqueue_noprof\0"
	"__ubsan_handle_load_invalid_value\0"
	"strlen\0"
	"dev_kfree_skb_any_reason\0"
	"cfg80211_report_obss_beacon_khz\0"
	"regulatory_set_wiphy_regd\0"
	"param_ops_int\0"
	"skb_append\0"
	"debugfs_create_dir\0"
	"pci_write_config_word\0"
	"get_fw_path\0"
	"generic_file_llseek\0"
	"_raw_spin_unlock\0"
	"simple_read_from_buffer\0"
	"cfg80211_connect_done\0"
	"cfg80211_unlink_bss\0"
	"__cfg80211_get_bss\0"
	"wiphy_free\0"
	"msleep\0"
	"ktime_get_with_offset\0"
	"cfg80211_cqm_rssi_notify\0"
	"__SCT__might_resched\0"
	"kmalloc_caches\0"
	"__trace_set_current_state\0"
	"netdev_info\0"
	"kmem_cache_destroy\0"
	"mutex_init_generic\0"
	"skb_queue_head\0"
	"flush_work\0"
	"cfg80211_rx_unprot_mlme_mgmt\0"
	"filp_open\0"
	"free_irq\0"
	"is_vmalloc_addr\0"
	"usb_alloc_urb\0"
	"cfg80211_mgmt_tx_status_ext\0"
	"regulatory_set_wiphy_regd_sync\0"
	"cfg80211_rx_unexpected_4addr_frame\0"
	"usb_anchor_urb\0"
	"__check_object_size\0"
	"rtnl_unlock\0"
	"wakeup_source_register\0"
	"release_firmware\0"
	"down_timeout\0"
	"__list_add_valid_or_report\0"
	"usb_free_urb\0"
	"_copy_from_user\0"
	"eth_mac_addr\0"
	"pci_enable_device\0"
	"skb_put\0"
	"__rcu_read_lock\0"
	"iwe_stream_add_event\0"
	"cfg80211_scan_done\0"
	"__msecs_to_jiffies\0"
	"__kmalloc_noprof\0"
	"consume_skb\0"
	"memmove\0"
	"get_adap_test\0"
	"snprintf\0"
	"complete\0"
	"queue_work_on\0"
	"cfg80211_remain_on_channel_expired\0"
	"cfg80211_cac_event\0"
	"skb_dequeue\0"
	"__init_swait_queue_head\0"
	"finish_wait\0"
	"cfg80211_register_netdevice\0"
	"dma_unmap_page_attrs\0"
	"__sw_hweight32\0"
	"request_firmware\0"
	"usb_register_driver\0"
	"scnprintf\0"
	"__pci_register_driver\0"
	"up\0"
	"iounmap\0"
	"aicwf_rxbuff_size_get\0"
	"ieee80211_chandef_to_operating_class\0"
	"pci_disable_msi\0"
	"pci_request_regions\0"
	"memcpy\0"
	"regulatory_hint\0"
	"kfree\0"
	"__trace_bprintk\0"
	"timer_delete\0"
	"get_userconfig_txpwr_idx\0"
	"cfg80211_external_auth_request\0"
	"prepare_to_wait_event\0"
	"netdev_warn\0"
	"kthread_should_stop\0"
	"timer_delete_sync\0"
	"__wake_up\0"
	"cfg80211_new_sta\0"
	"_raw_spin_lock_irqsave\0"
	"pci_ioremap_bar\0"
	"sched_set_fifo_low\0"
	"cfg80211_disconnected\0"
	"ether_setup\0"
	"pci_unregister_driver\0"
	"netdev_err\0"
	"__fentry__\0"
	"wake_up_process\0"
	"dev_driver_string\0"
	"dev_addr_mod\0"
	"eth_type_trans\0"
	"__x86_indirect_thunk_rax\0"
	"dma_map_page_attrs\0"
	"pm_wakeup_ws_event\0"
	"alloc_netdev_mqs\0"
	"wiphy_new_nm\0"
	"dump_stack\0"
	"_printk\0"
	"cfg80211_ready_on_channel\0"
	"strncasecmp\0"
	"__ref_stack_chk_guard\0"
	"schedule\0"
	"schedule_timeout\0"
	"cfg80211_classify8021d\0"
	"__tracepoint_sched_set_state_tp\0"
	"__stack_chk_fail\0"
	"queue_delayed_work_on\0"
	"_raw_spin_unlock_bh\0"
	"__kmalloc_large_noprof\0"
	"wiphy_register\0"
	"__cfg80211_alloc_reply_skb\0"
	"__copy_overflow\0"
	"usb_kill_anchored_urbs\0"
	"strnlen\0"
	"cfg80211_put_bss\0"
	"netif_device_detach\0"
	"cfg80211_roamed\0"
	"cfg80211_ch_switch_notify\0"
	"__x86_indirect_thunk_rdx\0"
	"usb_submit_urb\0"
	"__SCT__WARN_trap\0"
	"netif_device_attach\0"
	"skb_copy_expand\0"
	"skb_queue_tail\0"
	"print_hex_dump\0"
	"module_layout\0"
;

MODULE_INFO(depends, "cfg80211,aic_load_fw");

MODULE_ALIAS("usb:vA69Cp8801d*dc*dsc*dp*icFFiscFFipFFin*");
MODULE_ALIAS("usb:vA69Cp8D81d*dc*dsc*dp*icFFiscFFipFFin*");
MODULE_ALIAS("usb:vA69Cp8D41d*dc*dsc*dp*icFFiscFFipFFin*");
MODULE_ALIAS("usb:vA69Cp88DCd*dc*dsc*dp*icFFiscFFipFFin*");
MODULE_ALIAS("usb:vA69Cp88DDd*dc*dsc*dp*ic*isc*ip*in*");
MODULE_ALIAS("usb:v368Bp8D91d*dc*dsc*dp*icFFiscFFipFFin*");
MODULE_ALIAS("usb:v368Bp8D99d*dc*dsc*dp*ic*isc*ip*in*");
MODULE_ALIAS("usb:v368Bp8D45d*dc*dsc*dp*icFFiscFFipFFin*");
MODULE_ALIAS("usb:v368Bp8D46d*dc*dsc*dp*icFFiscFFipFFin*");
MODULE_ALIAS("usb:v368Bp8D47d*dc*dsc*dp*icFFiscFFipFFin*");
MODULE_ALIAS("usb:v368Bp8D48d*dc*dsc*dp*icFFiscFFipFFin*");
MODULE_ALIAS("usb:v368Bp8D49d*dc*dsc*dp*icFFiscFFipFFin*");
MODULE_ALIAS("usb:v368Bp8D4Ad*dc*dsc*dp*icFFiscFFipFFin*");
MODULE_ALIAS("usb:v368Bp8871d*dc*dsc*dp*icFFiscFFipFFin*");
MODULE_ALIAS("usb:v368Bp8870d*dc*dsc*dp*icFFiscFFipFFin*");

MODULE_INFO(srcversion, "97F0114D73A8991251176BA");
