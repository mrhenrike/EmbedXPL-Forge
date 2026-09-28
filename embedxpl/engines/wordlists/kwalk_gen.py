"""
kwalk_gen.py - Keyboard walk password generator.

Generates password candidates based on physical keyboard adjacency walks.
Supports multiple layouts (QWERTY, AZERTY, QWERTZ, Dvorak, custom) and
8-directional movement (N/S/E/W + diagonals) with configurable parameters.

Inspired by hashcat's kwprocessor (kwp), reimplemented in pure Python with
extended layout support.

Author: André Henrique (@mrhenrike)
Version: 1.0.0
"""
from __future__ import annotations

import itertools
import logging
from typing import Generator, Optional

logger = logging.getLogger(__name__)

LAYOUTS: dict[str, list[list[str]]] = {
    "qwerty": [
        list("`1234567890-="),
        list("qwertyuiop[]\\"),
        list("asdfghjkl;'"),
        list("zxcvbnm,./"),
    ],
    "qwerty_shift": [
        list("~!@#$%^&*()_+"),
        list("QWERTYUIOP{}|"),
        list('ASDFGHJKL:"'),
        list("ZXCVBNM<>?"),
    ],
    "azerty": [
        list("²&é\"'(-è_çà)="),
        list("azertyuiop^$"),
        list("qsdfghjklmù*"),
        list("wxcvbn,;:!"),
    ],
    "qwertz": [
        list("^1234567890ß´"),
        list("qwertzuiopü+"),
        list("asdfghjklöä#"),
        list("yxcvbnm,.-"),
    ],
    "dvorak": [
        list("`1234567890[]"),
        list("',.pyfgcrl/=\\"),
        list("aoeuidhtns-"),
        list(";qjkxbmwvz"),
    ],
    "numpad": [
        list("789"),
        list("456"),
        list("123"),
        list("0."),
    ],
}

DIRECTIONS = {
    "E":  (0, 1),
    "W":  (0, -1),
    "S":  (1, 0),
    "N":  (-1, 0),
    "SE": (1, 1),
    "SW": (1, -1),
    "NE": (-1, 1),
    "NW": (-1, -1),
}

DIR_BY_IDX = {
    "0": "N", "1": "NE", "2": "E", "3": "SE",
    "4": "S", "5": "SW", "6": "W", "7": "NW",
}


def _build_adjacency(layout: list[list[str]]) -> dict[str, dict[str, str]]:
    """Build adjacency map from a keyboard layout.

    Returns:
        Dict mapping each character to {direction: adjacent_char}.
    """
    adj: dict[str, dict[str, str]] = {}
    for r, row in enumerate(layout):
        for c, char in enumerate(row):
            if not char:
                continue
            adj[char] = {}
            for direction, (dr, dc) in DIRECTIONS.items():
                nr, nc = r + dr, c + dc
                if 0 <= nr < len(layout) and 0 <= nc < len(layout[nr]):
                    neighbor = layout[nr][nc]
                    if neighbor:
                        adj[char][direction] = neighbor
    return adj


def _merge_layouts(*layout_names: str) -> dict[str, dict[str, str]]:
    """Merge adjacency maps from multiple layouts."""
    merged: dict[str, dict[str, str]] = {}
    for name in layout_names:
        layout = LAYOUTS.get(name, [])
        if not layout:
            continue
        adj = _build_adjacency(layout)
        for char, neighbors in adj.items():
            if char not in merged:
                merged[char] = {}
            merged[char].update(neighbors)
    return merged


def generate_walks(
    min_length: int = 4,
    max_length: int = 10,
    layouts: Optional[list[str]] = None,
    directions: Optional[list[str]] = None,
    max_direction_changes: int = 3,
    include_shift: bool = True,
    start_chars: Optional[str] = None,
    max_candidates: int = 0,
) -> Generator[str, None, None]:
    """Generate keyboard walk passwords.

    Args:
        min_length: Minimum walk length.
        max_length: Maximum walk length.
        layouts: Layout names to use (default: ["qwerty"]).
        directions: Direction names to allow (default: all 8).
        max_direction_changes: Max number of direction changes per walk.
        include_shift: Include shifted layer (uppercase + symbols).
        start_chars: Restrict starting characters (None = all).
        max_candidates: Maximum candidates (0 = unlimited).

    Yields:
        Keyboard walk password strings.
    """
    if layouts is None:
        layouts = ["qwerty"]

    layout_names = list(layouts)
    if include_shift:
        for name in list(layout_names):
            shifted = f"{name}_shift"
            if shifted in LAYOUTS and shifted not in layout_names:
                layout_names.append(shifted)

    adjacency = _merge_layouts(*layout_names)
    if not adjacency:
        return

    allowed_dirs = set(directions) if directions else set(DIRECTIONS.keys())

    starters = list(start_chars) if start_chars else sorted(adjacency.keys())
    starters = [s for s in starters if s in adjacency]

    seen: set[str] = set()
    count = 0

    for start in starters:
        for walk in _dfs_walk(
            adjacency, start, min_length, max_length,
            allowed_dirs, max_direction_changes,
        ):
            if walk not in seen:
                seen.add(walk)
                yield walk
                count += 1
                if max_candidates and count >= max_candidates:
                    return


def _parse_route_dirs(route: str) -> list[str]:
    """Convert kwprocessor-style route string to direction names."""
    dirs: list[str] = []
    for ch in route.replace(",", "").replace(" ", "").replace("-", ""):
        upper = ch.upper()
        if upper in DIRECTIONS:
            dirs.append(upper)
        elif ch in DIR_BY_IDX:
            dirs.append(DIR_BY_IDX[ch])
    return dirs


def walk_route(
    start: str,
    route: str,
    layouts: Optional[list[str]] = None,
    include_shift: bool = True,
) -> Optional[str]:
    """Follow an explicit direction route from a starting key."""
    if not start or not route:
        return None

    layout_names = list(layouts or ["qwerty"])
    if include_shift:
        for name in list(layout_names):
            shifted = f"{name}_shift"
            if shifted in LAYOUTS and shifted not in layout_names:
                layout_names.append(shifted)

    adjacency = _merge_layouts(*layout_names)
    if start not in adjacency:
        return None

    path = start
    current = start
    for direction in _parse_route_dirs(route):
        nxt = adjacency.get(current, {}).get(direction)
        if not nxt:
            return None
        path += nxt
        current = nxt
    return path


def load_route_file(filepath: str) -> list[tuple[str, str]]:
    """Load routes from a kwprocessor-style file (start + direction digits per line)."""
    from pathlib import Path

    routes: list[tuple[str, str]] = []
    for line in Path(filepath).read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            start, dirs = line.split(":", 1)
        elif "," in line:
            start, dirs = line.split(",", 1)
        else:
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            start, dirs = parts
        start = start.strip()
        dirs = dirs.strip()
        if start and dirs:
            routes.append((start, dirs))
    return routes


def generate_routes(
    routes: list[tuple[str, str]],
    layouts: Optional[list[str]] = None,
    include_shift: bool = True,
    min_length: int = 0,
    max_length: int = 64,
) -> Generator[str, None, None]:
    """Generate passwords from explicit keyboard routes."""
    seen: set[str] = set()
    for start, route in routes:
        walk = walk_route(start, route, layouts=layouts, include_shift=include_shift)
        if not walk:
            continue
        if min_length and len(walk) < min_length:
            continue
        if max_length and len(walk) > max_length:
            continue
        if walk not in seen:
            seen.add(walk)
            yield walk


def _dfs_walk(
    adj: dict[str, dict[str, str]],
    start: str,
    min_len: int,
    max_len: int,
    allowed_dirs: set[str],
    max_changes: int,
) -> Generator[str, None, None]:
    """DFS-based walk enumeration from a starting character.

    Uses iterative DFS with a stack to avoid recursion depth issues.

    Yields:
        Walk strings of length [min_len, max_len].
    """
    stack: list[tuple[str, str, int]] = [(start, "", 0)]

    while stack:
        current_path, last_dir, dir_changes = stack.pop()

        if len(current_path) >= min_len:
            yield current_path

        if len(current_path) >= max_len:
            continue

        last_char = current_path[-1]
        neighbors = adj.get(last_char, {})

        for direction, next_char in neighbors.items():
            if direction not in allowed_dirs:
                continue

            new_changes = dir_changes
            if last_dir and direction != last_dir:
                new_changes += 1

            if new_changes > max_changes:
                continue

            stack.append((current_path + next_char, direction, new_changes))


def get_layout_info() -> dict[str, dict]:
    """Return information about available layouts."""
    info = {}
    for name, layout in LAYOUTS.items():
        chars = set()
        for row in layout:
            chars.update(c for c in row if c)
        info[name] = {
            "rows": len(layout),
            "chars": len(chars),
            "sample": "".join(layout[0][:10]) if layout else "",
        }
    return info


def handle_kwalk(args, ctx: dict) -> Optional[Generator[str, None, None]]:
    """CLI handler for keyboard walk generation.

    Args:
        args: Parsed CLI arguments.
        ctx: Global execution context.

    Returns:
        Generator yielding walk candidates, or None.
    """
    if getattr(args, "list_layouts", False):
        info = get_layout_info()
        lines = ["Available keyboard layouts:"]
        for name, data in info.items():
            lines.append(f"  {name:20s} {data['rows']} rows, {data['chars']:3d} chars  [{data['sample']}...]")
        return iter(["\n".join(lines)])

    layout_str = getattr(args, "layout", "qwerty") or "qwerty"
    layouts = [l.strip() for l in layout_str.split(",")]

    route_file = getattr(args, "route_file", None)
    route_arg = getattr(args, "route", None)
    if route_file or route_arg:
        routes: list[tuple[str, str]] = []
        if route_file:
            routes.extend(load_route_file(route_file))
        if route_arg:
            if ":" in route_arg:
                start, dirs = route_arg.split(":", 1)
            elif "," in route_arg:
                start, dirs = route_arg.split(",", 1)
            else:
                start, dirs = route_arg.split(None, 1) if " " in route_arg else (route_arg[0], route_arg[1:])
            routes.append((start.strip(), dirs.strip()))
        return generate_routes(
            routes,
            layouts=layouts,
            include_shift=not getattr(args, "no_shift", False),
            min_length=getattr(args, "min_len", 4),
            max_length=getattr(args, "max_len", 10),
        )

    dir_str = getattr(args, "directions", None)
    directions = [d.strip().upper() for d in dir_str.split(",")] if dir_str else None

    return generate_walks(
        min_length=getattr(args, "min_len", 4),
        max_length=getattr(args, "max_len", 10),
        layouts=layouts,
        directions=directions,
        max_direction_changes=getattr(args, "max_changes", 3),
        include_shift=not getattr(args, "no_shift", False),
        start_chars=getattr(args, "start_chars", None),
        max_candidates=getattr(args, "limit", 0) or 0,
    )
