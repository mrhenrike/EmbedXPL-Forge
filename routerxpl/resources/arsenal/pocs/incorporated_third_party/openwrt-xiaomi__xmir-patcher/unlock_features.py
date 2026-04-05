#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time

import xmir_base
from gateway import *

cwd = os.path.dirname(os.path.abspath(__file__))

gw = Gateway()

FN_lua       = f'tmp/XQFeatures.lua'
fn_lua       = '/tmp/XQFeatures.lua'
FN_patch     = f'tmp/unlockf_patch.sh'
fn_patch     = '/tmp/unlockf_patch.sh'
FN_install   = f'tmp/unlockf_install.sh'
fn_install   = '/tmp/unlockf_install.sh'
FN_uninstall = f'tmp/unlockf_uninstall.sh'
fn_uninstall = '/tmp/unlockf_uninstall.sh'

os.makedirs('tmp', exist_ok = True)

DEF_FEATURES = {
    "system": {
        "shutdown":               "0",
        "downloadlogs":           "0",
        "i18n":                   "0",
        "infileupload":           "1",
        "task":                   "0",
        "upnp":                   "1",
        "new_update":             "1",
        "multiwan":               "0", # def: 0   # misc.features.multiwan
        "support_1000_dhcp":      "1",
        "ipv6_wired":             "0",
        "ipv6_wired_v2":          "1",
        "plugin_install":         "0", # def: 0
        "GdprPrivacy":            "1",
        "international":          "1",
        "ipv6oversea":            "0",
        "set_router_location":    "0",
        "upgraded_light_color":   "1",
        "change_time":            "0", # def: 0
        "newRouterPwd":           "1",
        "https":                  "1",
        "ipv6_passthrough_relay": "1",
        "vpn_init":               "1",
        "mesh_bhtype_mode":       "0",
        "ipmaccheck":             "0",
        "map_e":                  "1",
        "dslite":                 "1",
        "map_e_ocn":              "1",
        "cpe":                    "0", # def: 0  # CPE 3G/4G/5G modem
    },
    "wifi": {
        "wifi24":          "1",
        "wifi50":          "1",
        "wifiguest":       "1",
        "wifimerge":       "1",
        "wifi_mu_mimo":    "0",
        "twt":             "1",
        "mlo":             "1",
        "mlo_vap":         "1",
        "split5g":         "0",
        "silence_switch":  "0",
        "wifi_access_ctl": "0",    # misc.features.supportWifiAccessCtl # wifiaccess.cfg.enable
        "iot_dev":         "0",    # misc.features.iot_dev
        "easymesh_switch": "0",
    },
    "apmode": {
        "wifiapmode": "1",     # misc.features.supportWifiAp
        "lanapmode":  "1",
    },
    "netmode": {
        "elink":      "1",
        "net2.5G":    "0",
        "net10G":     "0",
    },
    "apps": {
        "apptc":             "0",
        "qos":               "1",
        "dhcpMsg":           "1",
        "upnp":              "1",
        "nfc":               "0",
        "wanLan":            "1",
        "mipctlv2":          "0",
        "lanPort":           "1",
        "xqdatacenter":      "1",
        "baidupan":          "0",
        "timemachine":       "0",
        "storage":           "0",
        "samba":             "0",
        "docker":            "0",
        "swapmask":          "3", # 0..7
        "ports_custom":      "1",
        "LED_control":       "1", # 0..7
        "firewall":          "0",
        "local_gw_security": "0",
        "download":          "0",
        "temp_control":      "0",
        "sec_center":        "0", # 0..2
        "sfp":               "0",
        "game_port":         "0", # def: 0   # misc.features.game   # misc.wireless.wl_if_count=3
        "lan_lag":           "1",
        "telnet":            "0",
        "wifi_optimize":     "0",
    },
    "hardware": {
        "usb":        "0",
        "usb_deploy": "0",
        "disk":       "0",
    }
}

FEATURES = DEF_FEATURES.copy()
patched_features = { }

def patch_feature(node_name, fname, value, cfg_patch = None):
    FEATURES[node_name][fname] = value
    pname = f'{node_name}.{fname}'
    if pname not in patched_features:
        patched_features[pname] = [ ]
    if cfg_patch:
        patched_features[pname].extend(cfg_patch)

####################################################################################
# Edit me please
patch_feature('system', 'i18n', "1")
patch_feature('system', 'multiwan', "1", [ "misc.features.multiwan=1" ] )
patch_feature('system', 'plugin_install', "1")
patch_feature('system', 'change_time', "1")
patch_feature('wifi', 'wifi_access_ctl', "1", [ "misc.features.supportWifiAccessCtl=1", "wifiaccess.cfg.enable=1" ] )
# patch_feature('apps', 'game_port', "1", [ "misc.features.game=1" ] )
# patch_feature('apps', '__w3__', "1", [ "misc.wireless.wl_if_count=3" ] )
patch_feature('apps', 'baidupan', "1")
#
####################################################################################

lua_table = [ ]
lua_table.append('FEATURES = {')

def parse_feature(depth, elem_dict):
    prefix = '    ' * depth if depth >= 1 else ''
    for key, elem in elem_dict.items():
        if isinstance(elem, dict):
            lua_table.append(prefix + f'["{key}"] = ' + '{')
            parse_feature(depth + 1, elem)
        else:    
            if isinstance(elem, int) or isinstance(elem, float):
                value = f'{elem}'
            else:
                value = f'"{elem}"'
            lua_table.append(prefix + f'["{key}"] = {value},')
            if key == list(elem_dict)[-1]:
                lua_table.append(prefix + f'["__end__"] = "0"')
                prefix_new = '    ' * (depth - 1) if depth >= 2 else ''
                lua_table.append(prefix_new + '},')

parse_feature(1, FEATURES)
lua_table[-1] = '    }'
lua_table.append('}')

XQFeatures = '''#!/usr/bin/lua
module "xiaoqiang.XQFeatures"
'''
XQFeatures += '\n' + '\n'.join(lua_table) + '\n'
with open(FN_lua, 'w', newline = '\n') as file:
    file.write(XQFeatures)

unlockf_patch = '''#!/bin/sh
INST_FLAG_FN=/tmp/unlockf_patch.log

[ -f $INST_FLAG_FN ] && return 0
[ -s $INST_FLAG_FN ] && return 0
: > $INST_FLAG_FN

STOR_DIR=/etc/crontabs/patches/unlockf
TARGET_DIR=/usr/lib/lua/xiaoqiang
TARGET_FN=XQFeatures.lua
TARGET_FILENAME=$TARGET_DIR/$TARGET_FN
TARGET_STOR_ORIG=$STOR_DIR/$TARGET_FN.orig
TARGET_STOR_NEW=$STOR_DIR/$TARGET_FN

if mount | grep -q " on $TARGET_FILENAME " ; then
    return 1
fi
if [ ! -f $TARGET_FILENAME ]; then
	return 1
fi
if [ ! -f $TARGET_STOR_NEW ]; then
    return 1
fi
if [ ! -f $TARGET_STOR_ORIG ]; then
    cp -f $TARGET_FILENAME $TARGET_STOR_ORIG 
fi
mount --bind $TARGET_STOR_NEW $TARGET_FILENAME

### patch misc config ###

uci set misc.features.xmir_unlockf=1
uci commit misc

echo "unlockf enabled" > $INST_FLAG_FN

/etc/init.d/rpcd reload
'''
misc_patch = ''
for keyname, value in patched_features.items():
    vlist = value if isinstance(value, list) else [ value ]
    for val in vlist:
        if val:
            cfg_fn = val.split('.')[0]
            misc_patch += f'uci set {val}' + '\n'
            misc_patch += f'uci commit {cfg_fn}' + '\n'

unlockf_patch = unlockf_patch.replace('### patch misc config ###', misc_patch)

with open(FN_patch, 'w', newline = '\n') as file:
    file.write(unlockf_patch)

unlockf_install = '''#!/bin/sh
INST_FLAG_FN=/tmp/unlockf_patch.log

STOR_DIR=/etc/crontabs/patches/unlockf
TARGET_DIR=/usr/lib/lua/xiaoqiang
TARGET_FN=XQFeatures.lua
TARGET_FILENAME=$TARGET_DIR/$TARGET_FN
TARGET_STOR_ORIG=$STOR_DIR/$TARGET_FN.orig
TARGET_STOR_NEW=$STOR_DIR/$TARGET_FN
STOR_BACKUP_DIR=$STOR_DIR/backup

if [ ! -f /tmp/$TARGET_FN ]; then
    return 1
fi
if [ ! -d $STOR_DIR ]; then
    mkdir -p $STOR_DIR
    chown root $STOR_DIR
    chmod 0755 $STOR_DIR
fi

FIRST_INSTALL=0
if [ ! -d $STOR_BACKUP_DIR ]; then
    FIRST_INSTALL=1
    mkdir -p $STOR_BACKUP_DIR
    [ -f /etc/config/misc ] && cp -f /etc/config/misc $STOR_BACKUP_DIR/misc
fi
if mount | grep -q " on $TARGET_DIR type tmpfs" ; then
    umount -l $TARGET_DIR
fi
if mount | grep -q " on $TARGET_FILENAME " ; then
    umount -l $TARGET_FILENAME
fi
if [ ! -f $TARGET_STOR_ORIG ]; then
    cp -f $TARGET_FILENAME $TARGET_STOR_ORIG
fi
mv -f /tmp/$TARGET_FN $TARGET_STOR_NEW 
mv -f /tmp/unlockf_patch.sh $STOR_DIR/
chmod +x $STOR_DIR/unlockf_patch.sh

FILE_CRON=/etc/crontabs/root
if [ -f $FILE_CRON ]; then
    grep -v "/unlockf_patch.sh" $FILE_CRON > $FILE_CRON.new || echo "" > $FILE_CRON.new
    echo "*/1 * * * * $STOR_DIR/unlockf_patch.sh >/dev/null 2>&1" >> $FILE_CRON.new
    mv $FILE_CRON.new $FILE_CRON
fi
uci set firewall.auto_unlockf_patch=include
uci set firewall.auto_unlockf_patch.type='script'
uci set firewall.auto_unlockf_patch.path="$STOR_DIR/unlockf_patch.sh"
uci set firewall.auto_unlockf_patch.enabled='1'
uci commit firewall

rm -f $INST_FLAG_FN

# run patch
$STOR_DIR/unlockf_patch.sh

luci-reload
rm -f /tmp/luci-indexcache
luci-reload
'''
with open(FN_install, 'w', newline = '\n') as file:
    file.write(unlockf_install)

unlockf_uninstall = '''#!/bin/sh
INST_FLAG_FN=/tmp/unlockf_patch.log

STOR_DIR=/etc/crontabs/patches/unlockf
TARGET_DIR=/usr/lib/lua/xiaoqiang
TARGET_FN=XQFeatures.lua
TARGET_FILENAME=$TARGET_DIR/$TARGET_FN
TARGET_STOR_ORIG=$STOR_DIR/$TARGET_FN.orig
TARGET_STOR_NEW=$STOR_DIR/$TARGET_FN
STOR_BACKUP_DIR=$STOR_DIR/backup

if [ -d $STOR_BACKUP_DIR ]; then
    [ -s $STOR_BACKUP_DIR/misc ] && cp -f $STOR_BACKUP_DIR/misc /etc/config/misc
fi
FILE_CRON=/etc/crontabs/root
if grep -q '/unlockf_patch.sh' $FILE_CRON ; then
    grep -v "/unlockf_patch.sh" $FILE_CRON > $FILE_CRON.new
    mv $FILE_CRON.new $FILE_CRON
    /etc/init.d/cron restart
fi
if uci -q get firewall.auto_unlockf_patch ; then
    uci delete firewall.auto_unlockf_patch
    uci commit firewall
fi
if mount | grep -q " on $TARGET_DIR type tmpfs" ; then
    umount -l $TARGET_DIR
fi
if mount | grep -q " on $TARGET_FILENAME " ; then
    umount -l $TARGET_FILENAME
fi
rm -rf $STOR_BACKUP_DIR
rm -f $STOR_DIR/unlockf_patch.sh
rm -f $TARGET_STOR_NEW
rm -f $INST_FLAG_FN

/etc/init.d/rpcd reload
luci-reload
rm -f /tmp/luci-indexcache
luci-reload
'''
with open(FN_uninstall, 'w', newline = '\n') as file:
    file.write(unlockf_uninstall)

action = 'install'
if len(sys.argv) > 1:
    if sys.argv[1].startswith('u') or sys.argv[1].startswith('r'):
        action = 'uninstall'

if action == 'install':
    gw.upload(FN_lua, fn_lua)
    gw.upload(FN_patch, fn_patch)
    gw.upload(FN_install, fn_install)

gw.upload(FN_uninstall, fn_uninstall)

print("All files uploaded!")

print("Run scripts...")
run_script = fn_install if action == 'install' else fn_uninstall
gw.run_cmd(f"chmod +x {run_script} ; {run_script}", timeout = 17)

time.sleep(1.5)

gw.run_cmd(f"rm -f {fn_lua} ; rm -f {fn_patch} ; rm -f {fn_install} ; rm -f {fn_uninstall}")

print("Ready! The UnlockFeatures patch installed.")
