# Original: laboratory/bug-hunt/mikrotik/scripts/setup_users_groups.py
# Source: mrhenrike | SafeLabs security research
# Embedded in EmbedXPL-Forge native_src by @mrhenrike | Uniao Geek

#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: André Henrique (LinkedIn/X: @mrhenrike)
# Version: 1.0.0

"""Create/update RouterOS groups and limited users for lab hardening."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import Dict, List, Tuple

import paramiko


LOGGER = logging.getLogger("setup_users_groups")


GROUP_POLICIES: Dict[str, str] = {
    "safelabs-ftp-ro": "ftp,read",
    "safelabs-ssh-rw": "ssh,read,write,test",
    "safelabs-web-rw": "web,rest-api,read,write,test",
    "safelabs-web-ro": "web,rest-api,read",
    "safelabs-winbox-only": "read",
}


def parse_lab_creds(env_path: Path) -> Dict[str, Tuple[str, str]]:
    """Parse LAB_CRED_* entries from `.env` in `user:pass` format."""
    creds: Dict[str, Tuple[str, str]] = {}
    if not env_path.exists():
        return creds
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if not key.startswith("LAB_CRED_") or ":" not in value:
            continue
        username, password = value.split(":", 1)
        creds[key] = (username, password)
    return creds


def build_user_mapping(creds: Dict[str, Tuple[str, str]]) -> List[Tuple[str, str, str]]:
    """Build user->group mapping from known lab credentials."""
    required = {
        "LAB_CRED_INFO": "safelabs-ftp-ro",
        "LAB_CRED_ADM": "safelabs-ssh-rw",
        "LAB_CRED_MANAGER": "safelabs-web-rw",
        "LAB_CRED_USER": "safelabs-web-ro",
        "LAB_CRED_ADMINISTRATOR": "safelabs-winbox-only",
    }
    mappings: List[Tuple[str, str, str]] = []
    for cred_key, group_name in required.items():
        if cred_key not in creds:
            raise RuntimeError(f"Missing required credential in .env: {cred_key}")
        username, password = creds[cred_key]
        mappings.append((username, password, group_name))
    return mappings


def run_ssh_cmd(client: paramiko.SSHClient, command: str) -> Tuple[int, str, str]:
    """Run command over SSH and return exit code/stdout/stderr."""
    _, stdout, stderr = client.exec_command(command)
    out = stdout.read().decode("utf-8", errors="replace").strip()
    err = stderr.read().decode("utf-8", errors="replace").strip()
    code = stdout.channel.recv_exit_status()
    return code, out, err


def upsert_group(client: paramiko.SSHClient, name: str, policies: str) -> None:
    """Create group if missing, else update policy list."""
    cmd = (
        f':if ([:len [/user group find where name="{name}"]] = 0) do='
        f'{{/user group add name="{name}" policy="{policies}"}} '
        f'else={{/user group set [/user group find where name="{name}"] policy="{policies}"}}'
    )
    code, _, err = run_ssh_cmd(client, cmd)
    if code != 0:
        raise RuntimeError(f"Failed group upsert {name}: {err}")


def upsert_user(client: paramiko.SSHClient, username: str, password: str, group_name: str) -> None:
    """Create user if missing, else update group/password and enable account."""
    cmd = (
        f':if ([:len [/user find where name="{username}"]] = 0) do='
        f'{{/user add name="{username}" group="{group_name}" password="{password}" disabled=no}} '
        f'else={{/user set [/user find where name="{username}"] group="{group_name}" '
        f'password="{password}" disabled=no}}'
    )
    code, _, err = run_ssh_cmd(client, cmd)
    if code != 0:
        raise RuntimeError(f"Failed user upsert {username}: {err}")


def configure_logging() -> None:
    """Configure console logging."""
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )


def build_parser() -> argparse.ArgumentParser:
    """Build command-line parser."""
    parser = argparse.ArgumentParser(description="Setup MikroTik limited users/groups via SSH.")
    parser.add_argument("--target", required=True, help="Router target IP/hostname")
    parser.add_argument("-U", "--admin-user", default="admin", help="Admin username for SSH")
    parser.add_argument("-P", "--admin-pass", required=True, help="Admin password for SSH")
    parser.add_argument("--ssh-port", type=int, default=22, help="SSH port")
    parser.add_argument("--env-file", default=".env", help="Path to lab .env with LAB_CRED_* entries")
    parser.add_argument("--dry-run", action="store_true", help="Validate mapping only, do not apply")
    return parser


def main() -> int:
    """Entrypoint."""
    configure_logging()
    args = build_parser().parse_args()

    creds = parse_lab_creds(Path(args.env_file))
    mapping = build_user_mapping(creds)
    LOGGER.info("Loaded %d LAB_CRED entries. Planned users: %s", len(creds), [m[0] for m in mapping])

    if args.dry_run:
        LOGGER.info("Dry-run complete. No changes applied.")
        return 0

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=args.target,
            port=args.ssh_port,
            username=args.admin_user,
            password=args.admin_pass,
            timeout=8,
            banner_timeout=8,
            auth_timeout=8,
            look_for_keys=False,
            allow_agent=False,
        )
        for group_name, policy in GROUP_POLICIES.items():
            upsert_group(client, group_name, policy)
            LOGGER.info("Group ensured: %s", group_name)
        for username, password, group_name in mapping:
            upsert_user(client, username, password, group_name)
            LOGGER.info("User ensured: %s -> %s", username, group_name)
        LOGGER.info("User/group setup completed successfully.")
        return 0
    except Exception as exc:
        LOGGER.error("User/group setup failed: %s", exc)
        return 1
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
