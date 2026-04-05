"""
This plugin requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from badges.cmd import Command

from pwny.api import *
from pwny.types import *

from hatsploit.lib.core.plugin import Plugin


SCHTASK_LIST = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL)
SCHTASK_CREATE = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 1)
SCHTASK_DELETE = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 2)
SCHTASK_RUN = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 3)

TLV_TYPE_ST_NAME = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
TLV_TYPE_ST_PATH = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 1)
TLV_TYPE_ST_STATE = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE)
TLV_TYPE_ST_CMD = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 2)
TLV_TYPE_ST_ARGS = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 3)
TLV_TYPE_ST_XML = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 4)
TLV_TYPE_ST_GROUP = tlv_custom_type(TLV_TYPE_GROUP, TAB_BASE, API_TYPE)
TLV_TYPE_ST_FOLDER = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 5)

TASK_STATE_NAMES = {
    0: "Unknown",
    1: "Disabled",
    2: "Queued",
    3: "Ready",
    4: "Running",
}

TASK_XML_TEMPLATE = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>{description}</Description>
  </RegistrationInfo>
  <Triggers>
    {trigger}
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{command}</Command>
      <Arguments>{arguments}</Arguments>
    </Exec>
  </Actions>
</Task>"""


class HatSploitPlugin(Plugin):
    def __init__(self):
        super().__init__({
            'Name': "Scheduled Tasks Plugin",
            'Plugin': "schtasks",
            'Authors': [
                'EntySec - plugin developer',
            ],
            'Description': "Enumerate, create, run, and delete scheduled tasks via COM.",
        })

        self.commands = [
            Command({
                'Category': "manage",
                'Name': "schtask_list",
                'Description': "List scheduled tasks.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('-f', '--folder'),
                        {
                            'help': "Task folder to enumerate (default: \\).",
                            'metavar': 'PATH',
                            'default': '\\',
                        }
                    ),
                ]
            }),
            Command({
                'Category': "manage",
                'Name': "schtask_create",
                'Description': "Create a scheduled task.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('name',),
                        {
                            'help': "Name of the task to create.",
                        }
                    ),
                    (
                        ('-c', '--command'),
                        {
                            'help': "Command to execute (creates a logon trigger task).",
                            'metavar': 'CMD',
                        }
                    ),
                    (
                        ('-a', '--args'),
                        {
                            'help': "Arguments for the command.",
                            'metavar': 'ARGS',
                            'default': '',
                        }
                    ),
                    (
                        ('-x', '--xml'),
                        {
                            'help': "Local XML definition file for the task.",
                            'metavar': 'FILE',
                        }
                    ),
                ]
            }),
            Command({
                'Category': "manage",
                'Name': "schtask_delete",
                'Description': "Delete a scheduled task.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('name',),
                        {
                            'help': "Name of the task to delete.",
                        }
                    ),
                ]
            }),
            Command({
                'Category': "manage",
                'Name': "schtask_run",
                'Description': "Run a scheduled task immediately.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('name',),
                        {
                            'help': "Name of the task to run.",
                        }
                    ),
                ]
            }),
        ]

    # -----------------------------------------------------------------
    # List
    # -----------------------------------------------------------------

    def schtask_list(self, args):
        result = self.session.send_command(
            tag=SCHTASK_LIST,
            plugin=self.plugin,
            args={
                TLV_TYPE_ST_FOLDER: args.folder,
            },
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to enumerate tasks!")
            return

        headers = ('Name', 'Path', 'State')
        data = []

        while True:
            entry = result.get_tlv(TLV_TYPE_ST_GROUP)
            if entry is None:
                break

            name_raw = entry.get_raw(TLV_TYPE_ST_NAME)
            path_raw = entry.get_raw(TLV_TYPE_ST_PATH)
            name = name_raw.decode('utf-8', errors='replace') if name_raw else ''
            path = path_raw.decode('utf-8', errors='replace') if path_raw else ''
            state_val = entry.get_int(TLV_TYPE_ST_STATE) or 0
            state = TASK_STATE_NAMES.get(state_val, str(state_val))
            data.append((name, path, state))

        if not data:
            self.print_warning("No tasks found.")
            return

        data.sort(key=lambda x: x[1])
        self.print_table('Scheduled Tasks', headers, *data)

    # -----------------------------------------------------------------
    # Create
    # -----------------------------------------------------------------

    def schtask_create(self, args):
        if args.xml:
            try:
                with open(args.xml, 'r') as f:
                    xml = f.read()
            except Exception as e:
                self.print_error(f"Failed to read XML file: {e}")
                return
        elif args.command:
            trigger = """<LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>"""

            xml = TASK_XML_TEMPLATE.format(
                description=f'Task created by Pwny: {args.name}',
                trigger=trigger,
                command=args.command,
                arguments=args.args,
            )
        else:
            self.print_error("Specify --command or --xml!")
            return

        result = self.session.send_command(
            tag=SCHTASK_CREATE,
            plugin=self.plugin,
            args={
                TLV_TYPE_ST_NAME: args.name,
                TLV_TYPE_ST_XML: xml,
            },
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to create task!")
            return

        self.print_success(f"Task '{args.name}' created.")

    # -----------------------------------------------------------------
    # Delete
    # -----------------------------------------------------------------

    def schtask_delete(self, args):
        result = self.session.send_command(
            tag=SCHTASK_DELETE,
            plugin=self.plugin,
            args={
                TLV_TYPE_ST_NAME: args.name,
            },
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to delete task!")
            return

        self.print_success(f"Task '{args.name}' deleted.")

    # -----------------------------------------------------------------
    # Run
    # -----------------------------------------------------------------

    def schtask_run(self, args):
        result = self.session.send_command(
            tag=SCHTASK_RUN,
            plugin=self.plugin,
            args={
                TLV_TYPE_ST_NAME: args.name,
            },
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to run task!")
            return

        self.print_success(f"Task '{args.name}' triggered.")

    def load(self):
        pass
