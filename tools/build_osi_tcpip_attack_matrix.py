#!/usr/bin/env python3
"""Build OSI/TCP-IP attack/test matrix CSV from curated catalog."""

from __future__ import annotations

# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek

import csv
import json
from pathlib import Path
from typing import Dict, List


def main() -> int:
    """Export normalized OSI protocol attack/test matrix."""
    repo_root = Path(__file__).resolve().parents[1]
    catalog_path = repo_root / "embedxpl" / "resources" / "catalogs" / "osi_tcpip_priority_matrix.json"
    payload = json.loads(catalog_path.read_text(encoding="utf-8"))
    layers: List[Dict[str, object]] = payload.get("layers", [])

    out_path = repo_root / ".log" / "osi_tcpip_attack_test_matrix.csv"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "osi_layer",
                "tcpip_layer",
                "layer_name",
                "protocol",
                "attack_vectors",
                "test_types",
                "priority_isp",
                "priority_corporate",
                "priority_ot_iiot",
            ],
        )
        writer.writeheader()
        for layer in layers:
            layer_attacks = [str(item) for item in layer.get("attack_matrix", [])]
            layer_tests = [str(item) for item in layer.get("test_matrix", [])]
            for proto in layer.get("protocols", []):
                proto_attacks = [str(item) for item in proto.get("attack_vectors", [])]
                proto_tests = [str(item) for item in proto.get("test_types", [])]
                priority = proto.get("priority_by_env", {})
                writer.writerow(
                    {
                        "osi_layer": layer.get("osi_layer", ""),
                        "tcpip_layer": layer.get("tcpip_layer", ""),
                        "layer_name": layer.get("layer_name", ""),
                        "protocol": proto.get("name", ""),
                        "attack_vectors": ";".join(proto_attacks if proto_attacks else layer_attacks),
                        "test_types": ";".join(proto_tests if proto_tests else layer_tests),
                        "priority_isp": priority.get("ISP", ""),
                        "priority_corporate": priority.get("Corporate", ""),
                        "priority_ot_iiot": priority.get("OT_IIoT", ""),
                    }
                )

    print("osi_tcpip_matrix_rows_written file={}".format(out_path.name))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
