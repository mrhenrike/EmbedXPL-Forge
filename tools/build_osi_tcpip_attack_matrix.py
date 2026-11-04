"""Build OSI/TCP-IP attack/test matrix CSV from curated catalog."""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Dict, List


def main() -> None:
    """Export normalized OSI protocol attack/test matrix."""
    root = Path(__file__).resolve().parent.parent
    catalog_path = root / "embedxpl" / "resources" / "catalogs" / "osi_tcpip_priority_matrix.json"
    out_path = root / "docs" / "osi_tcpip_attack_test_matrix.csv"

    if not catalog_path.exists():
        print(f"[WARN] Catalog not found: {catalog_path} — skipping.")
        return

    data = json.loads(catalog_path.read_text(encoding="utf-8"))
    layers: List[Dict] = data.get("layers", [])

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=[
            "osi_layer", "tcpip_layer", "layer_name", "protocol",
            "attack_vectors", "test_types",
        ])
        writer.writeheader()
        for layer in layers:
            for proto in layer.get("protocols", [layer.get("protocol", "")]):
                writer.writerow({
                    "osi_layer": layer.get("osi_layer", ""),
                    "tcpip_layer": layer.get("tcpip_layer", ""),
                    "layer_name": layer.get("name", ""),
                    "protocol": proto,
                    "attack_vectors": "|".join(layer.get("attack_vectors", [])),
                    "test_types": "|".join(layer.get("test_types", [])),
                })

    print(f"[OK] OSI/TCP-IP matrix written to {out_path}")


if __name__ == "__main__":
    main()
