"""
This plugin requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from badges.cmd import Command

from pwny.api import *
from pwny.types import *

from hatsploit.lib.core.plugin import Plugin


SERVICES_LIST = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL)

TLV_TYPE_SVC_NAME = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
TLV_TYPE_SVC_DISPLAY = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 1)
TLV_TYPE_SVC_STATE = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE)
TLV_TYPE_SVC_TYPE = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE + 1)
TLV_TYPE_SVC_PID = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE + 2)
TLV_TYPE_SVC_GROUP = tlv_custom_type(TLV_TYPE_GROUP, TAB_BASE, API_TYPE)

SERVICE_STOPPED = 1
SERVICE_START_PENDING = 2
SERVICE_STOP_PENDING = 3
SERVICE_RUNNING = 4
SERVICE_CONTINUE_PENDING = 5
SERVICE_PAUSE_PENDING = 6
SERVICE_PAUSED = 7

STATE_NAMES = {
    SERVICE_STOPPED: 'Stopped',
    SERVICE_START_PENDING: 'Starting',
    SERVICE_STOP_PENDING: 'Stopping',
    SERVICE_RUNNING: 'Running',
    SERVICE_CONTINUE_PENDING: 'Continuing',
    SERVICE_PAUSE_PENDING: 'Pausing',
    SERVICE_PAUSED: 'Paused',
}

# Known AV/EDR vendor signatures
AV_SIGNATURES = {
    'Windows Defender': [
        'windefend', 'msmpeng', 'mssense', 'securityhealthservice',
        'sense', 'wdnissvc',
    ],
    'Norton': [
        'norton', 'symantec', 'sepmaster', 'smc', 'ccsvchst', 'nswscsvc',
    ],
    'McAfee': [
        'mcafee', 'masvc', 'mfemms', 'macmnsvc', 'mfefire',
    ],
    'Kaspersky': [
        'kaspersky', 'avp', 'kavfs', 'klnagent',
    ],
    'Bitdefender': [
        'bitdefender', 'bdagent', 'vsserv', 'updatesrv',
    ],
    'ESET': [
        'eset', 'ekrn', 'egui',
    ],
    'Avast/AVG': [
        'avast', 'avg', 'avastsvc', 'avgsvc', 'avgnt',
    ],
    'Trend Micro': [
        'trendmicro', 'ntrtscan', 'tmccsf', 'tmlisten', 'tmsysev',
    ],
    'Sophos': [
        'sophos', 'savservice', 'sophossps',
    ],
    'CrowdStrike': [
        'crowdstrike', 'csfalconservice', 'csagent', 'csfalcon',
    ],
    'SentinelOne': [
        'sentinelagent', 'sentinelone', 'sentinelhelper',
    ],
    'Carbon Black': [
        'carbonblack', 'cbdefense', 'cbstream', 'cb.exe',
    ],
    'Cylance': [
        'cylance', 'cyoptics', 'cyprotect',
    ],
    'Malwarebytes': [
        'malwarebytes', 'mbamservice', 'mbam',
    ],
    'Webroot': [
        'webroot', 'wrsa', 'wrsvc',
    ],
    'F-Secure': [
        'fsecure', 'fsgk32', 'fsav32', 'fsdfwd',
    ],
    'Panda': [
        'panda', 'pavsrv', 'psanhost',
    ],
    'Comodo': [
        'comodo', 'cmdagent', 'cavwp',
    ],
}


class HatSploitPlugin(Plugin):
    def __init__(self):
        super().__init__({
            'Name': "Services Plugin",
            'Plugin': "services",
            'Authors': [
                'EntySec - plugin developer',
            ],
            'Description': "Enumerate Windows services and detect AV/EDR.",
        })

        self.commands = [
            Command({
                'Category': "gather",
                'Name': "services",
                'Description': "Enumerate Windows services.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('-l', '--list'),
                        {
                            'help': "List all services.",
                            'action': 'store_true',
                        }
                    ),
                    (
                        ('-r', '--running'),
                        {
                            'help': "Show only running services.",
                            'action': 'store_true',
                        }
                    ),
                    (
                        ('-f', '--filter'),
                        {
                            'help': "Filter services by name substring.",
                            'metavar': 'NAME',
                        }
                    ),
                ]
            }),
            Command({
                'Category': "gather",
                'Name': "av",
                'Description': "Detect installed antivirus and EDR products.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('-l', '--list'),
                        {
                            'help': "Scan services for known AV/EDR signatures.",
                            'action': 'store_true',
                        }
                    ),
                ]
            }),
        ]

    def services(self, args):
        services = self._enumerate_services()

        if services is None:
            self.print_error("Failed to enumerate services!")
            return

        headers = ('Name', 'Display Name', 'State', 'PID')
        data = []

        for name, display, state, pid in services:
            if args.running and state != SERVICE_RUNNING:
                continue

            if args.filter and args.filter.lower() not in name.lower():
                continue

            state_name = STATE_NAMES.get(state, f'Unknown({state})')
            pid_str = str(pid) if pid > 0 else '-'

            data.append((name, display, state_name, pid_str))

        if not data:
            self.print_warning("No matching services found.")
            return

        self.print_table("Services", headers, *data)

    def _enumerate_services(self):
        """Shared helper that fetches services from the implant."""

        result = self.session.send_command(
            tag=SERVICES_LIST,
            plugin=self.plugin,
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            return None

        services = []

        while True:
            entry = result.get_tlv(TLV_TYPE_SVC_GROUP)
            if entry is None:
                break

            name_raw = entry.get_raw(TLV_TYPE_SVC_NAME)
            display_raw = entry.get_raw(TLV_TYPE_SVC_DISPLAY)
            name = name_raw.decode('utf-8', errors='replace') if name_raw else ''
            display = display_raw.decode('utf-8', errors='replace') if display_raw else ''
            state = entry.get_int(TLV_TYPE_SVC_STATE) or 0
            pid = entry.get_int(TLV_TYPE_SVC_PID) or 0

            services.append((name, display, state, pid))

        return services

    def av(self, args):
        services = self._enumerate_services()

        if services is None:
            self.print_error("Failed to enumerate services!")
            return

        detected = {}

        for svc_name, svc_display, svc_state, svc_pid in services:
            combined = (svc_name + ' ' + svc_display).lower()

            for vendor, signatures in AV_SIGNATURES.items():
                for sig in signatures:
                    if sig in combined:
                        if vendor not in detected:
                            detected[vendor] = []
                        state_str = 'Running' if svc_state == SERVICE_RUNNING else 'Stopped'
                        detected[vendor].append((svc_name, svc_display, state_str))
                        break

        if not detected:
            self.print_warning("No known AV/EDR products detected.")
            return

        for vendor, entries in detected.items():
            self.print_information(f"%bold{vendor}%end")
            for svc_name, svc_display, state_str in entries:
                status_color = '%green' if state_str == 'Running' else '%red'
                self.print_information(
                    f"  {svc_name} ({svc_display}) [{status_color}{state_str}%end]"
                )

    def load(self):
        pass
