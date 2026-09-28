rule Stuxnet_S7_Hook {
    meta:
        description = "Detects Stuxnet S7 API hook DLL replacement"
        author = "TupaXPL-Forge - Andre Henrique (@mrhenrike)"
        reference = "https://github.com/Sadpainy/Stuxnet"
        severity = "CRITICAL"
        mitre = "T0873"
    strings:
        $s7api1 = "s7otbxdx.dll" ascii wide nocase
        $s7api2 = "s7otbxsx.dll" ascii wide nocase
        $export_write = "s7blk_write" ascii
        $export_read = "s7blk_read" ascii
        $export_find = "s7blk_find" ascii
        $mrxcls = "mrxcls.sys" ascii wide nocase
        $mrxnet = "mrxnet.sys" ascii wide nocase
        $wtr1 = "~WTR4141.tmp" ascii wide
        $wtr2 = "~WTR4132.tmp" ascii wide
        $sha256_v1 = "b6066aeeee4ebf45110a972c72882cd30036b94e35d985befc19aea5713f0cc9" ascii
    condition:
        2 of ($s7api*) or
        (1 of ($s7api*) and 1 of ($export_*)) or
        1 of ($mrxcls, $mrxnet) or
        1 of ($wtr*)
}

rule Stuxnet_Rootkit_Driver {
    meta:
        description = "Detects Stuxnet kernel-mode rootkit (SSDT hooking)"
        severity = "CRITICAL"
        mitre = "T0851"
    strings:
        $driver1 = "MRxCls" ascii wide
        $driver2 = "MRxNet" ascii wide
        $ssdt = "KeServiceDescriptorTable" ascii
        $fastio = "FastIoDispatch" ascii
        $ob1 = "OB1" ascii
        $ob35 = "OB35" ascii
    condition:
        1 of ($driver*) or
        ($ssdt and $fastio) or
        ($ob1 and $ob35 and 1 of ($s7api*))
}

rule Stuxnet_Dropper_LNK {
    meta:
        description = "Detects Stuxnet dropper LNK exploit components"
        severity = "HIGH"
        cve = "CVE-2010-2568"
    strings:
        $wtr_tmp1 = "~WTR4141" ascii wide
        $wtr_tmp2 = "~WTR4132" ascii wide
        $scr = "s7cntlD.scr" ascii wide
        $lnk_magic = { 4C 00 00 00 01 14 02 00 }
    condition:
        1 of ($wtr_tmp*) or
        $scr or
        ($lnk_magic at 0 and filesize < 5KB)
}

rule Stuxnet_PLC_Payload {
    meta:
        description = "Detects Stuxnet PLC frequency manipulation payload"
        severity = "CRITICAL"
        target = "Siemens S7-315, S7-417"
    strings:
        // 1410 Hz -> 2 Hz -> 1064 Hz attack sequence markers
        $freq_normal = { 82 05 }   // 1410 Hz (0x0582)
        $freq_attack = { 02 00 }   // 2 Hz attack
        $freq_alt    = { 28 04 }   // 1064 Hz (0x0428)
        $plc315 = { 15 03 }        // S7-315 CPU ID
        $plc417 = { 17 04 }        // S7-417 CPU ID
        $step7 = "Step 7" ascii wide nocase
    condition:
        ($freq_normal and $freq_attack) or
        ($plc315 and $step7) or
        ($plc417 and $step7)
}
