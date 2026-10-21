import atexit
import getopt
import itertools
import os
import signal
import sys
import traceback
from collections import Counter
from pathlib import Path

# Adaptation credits: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
from embedxpl.core.exploit.exceptions import EmbedXPLException
from embedxpl.core.exploit.exploit import GLOBAL_OPTS
from embedxpl.core.exploit.payloads import BasePayload
from embedxpl.core.exploit.printer import (
    PrinterThread,
    pprint_dict_in_order,
    print_error,
    print_info,
    print_status,
    print_success,
    print_table,
    print_warning,
    printer_queue,
)
from embedxpl.core.exploit.utils import (
    MODULES_DIR,
    WORDLISTS_DIR,
    humanize_path,
    import_exploit,
    index_modules,
    module_required,
    pythonize_path,
    stop_after,
)

try:
    import readline
except ImportError:
    class _ReadlineShim:
        """Fallback shim for platforms without GNU readline (e.g. Windows)."""

        __doc__ = ""

        @staticmethod
        def read_history_file(*args, **kwargs):
            return None

        @staticmethod
        def set_history_length(*args, **kwargs):
            return None

        @staticmethod
        def write_history_file(*args, **kwargs):
            return None

        @staticmethod
        def parse_and_bind(*args, **kwargs):
            return None

        @staticmethod
        def set_completer(*args, **kwargs):
            return None

        @staticmethod
        def set_completer_delims(*args, **kwargs):
            return None

        @staticmethod
        def get_line_buffer():
            return ""

        @staticmethod
        def get_begidx():
            return 0

        @staticmethod
        def get_endidx():
            return 0

    readline = _ReadlineShim()


def is_libedit():
    return isinstance(readline.__doc__, str) and "libedit" in readline.__doc__


class BaseInterpreter:
    history_file = os.path.expanduser("~/.history")
    history_length = 100
    global_help = ""

    def __init__(self):
        self.setup()
        self.banner = ""

    def setup(self):
        """ Initialization of third-party libraries

        Setting interpreter history.
        Setting appropriate completer function.

        :return:
        """
        if not os.path.exists(self.history_file):
            with open(self.history_file, "a+") as history:
                if is_libedit():
                    history.write("_HiStOrY_V2_\n\n")

        readline.read_history_file(self.history_file)
        readline.set_history_length(self.history_length)
        atexit.register(readline.write_history_file, self.history_file)

        readline.parse_and_bind("set enable-keypad on")

        readline.set_completer(self.complete)
        readline.set_completer_delims(" \t\n;")
        if is_libedit():
            readline.parse_and_bind("bind ^I rl_complete")
        else:
            readline.parse_and_bind("tab: complete")

    def parse_line(self, line):
        """ Split line into command and argument.

        :param line: line to parse
        :return: (command, argument, named_arguments)
        """
        kwargs = dict()
        command, _, arg = line.strip().partition(" ")
        args = arg.strip().split()
        for word in args:
            if '=' in word:
                (key, value) = word.split('=', 1)
                kwargs[key.lower()] = value
                arg = arg.replace(word, '')
        return command, ' '.join(arg.split()), kwargs

    @property
    def prompt(self):
        """ Returns prompt string """
        return ">>>"

    def get_command_handler(self, command):
        """ Parsing command and returning appropriate handler.

        :param command: command
        :return: command_handler
        """
        try:
            command_handler = getattr(self, "command_{}".format(command))
        except AttributeError:
            raise EmbedXPLException("Unknown command: '{}'".format(command))

        return command_handler

    def start(self):
        """ EmbedXPL main entry point. Starting interpreter loop. """

        if not sys.stdin.isatty():
            print_info("stdin is not a TTY. Ensure `stdin_open` and `tty` are set")
            sys.exit(1)

        # Banner figlet com stats em tempo real
        try:
            from embedxpl.core.banner import show_banner
            show_banner("embedxpl", version="v5.0.0")
        except Exception:
            if getattr(self, "banner", None):
                print_info(self.banner)
        print_warning("FOR AUTHORIZED PENETRATION TESTING ONLY. Operator assumes full responsibility.")
        print_warning("simulate=True enforced. Use 'set simulate false' to execute for real.")
        printer_queue.join()

        while True:
            try:
                command, args, kwargs = self.parse_line(input(self.prompt))
                if not command:
                    continue
                command_handler = self.get_command_handler(command)
                command_handler(args, **kwargs)
            except EmbedXPLException as err:
                print_error(err)
            except (EOFError, SystemExit):
                print_info()
                print_error("EmbedXPL stopped")
                os._exit(0)
            except KeyboardInterrupt:
                print_info()
                print_error("Use Ctrl+D to exit")
            finally:
                printer_queue.join()

    def complete(self, text, state):
        """Return the next possible completion for 'text'.

        If a command has not been entered, then complete against command list.
        Otherwise try to call complete_<command> to get list of completions.
        """
        if state == 0:
            original_line = readline.get_line_buffer()
            line = original_line.lstrip()
            stripped = len(original_line) - len(line)
            start_index = readline.get_begidx() - stripped
            end_index = readline.get_endidx() - stripped

            if start_index > 0:
                cmd, args, _ = self.parse_line(line)
                if cmd == "":
                    complete_function = self.default_completer
                else:
                    try:
                        complete_function = getattr(self, "complete_" + cmd)
                    except AttributeError:
                        complete_function = self.default_completer
            else:
                complete_function = self.raw_command_completer

            self.completion_matches = complete_function(text, line, start_index, end_index)

        try:
            return self.completion_matches[state]
        except IndexError:
            return None

    def commands(self, *ignored):
        """ Returns full list of interpreter commands.

        :param ignored:
        :return: full list of interpreter commands
        """
        return [command.rsplit("_").pop() for command in dir(self) if command.startswith("command_")]

    def raw_command_completer(self, text, line, start_index, end_index):
        """ Complete command w/o any argument """
        return [command for command in self.suggested_commands() if command.startswith(text)]

    def default_completer(self, *ignored):
        return []

    def suggested_commands(self):
        """ Entry point for intelligent tab completion.

        Overwrite this method to suggest suitable commands.

        :return: list of suitable commands
        """
        return self.commands()


