"""Analysis result model (read-only, deterministic)."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class FragmentAnalysis:
    snapshot_id: str = "snapshot-0"
    fragments: List[Dict[str, Any]] = field(default_factory=list)
    statistics: Dict[str, Any] = field(default_factory=dict)
    diagnostics: List[Dict[str, Any]] = field(default_factory=list)
    consistent: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "fragments": list(self.fragments),
            "statistics": dict(self.statistics),
            "diagnostics": list(self.diagnostics),
            "consistent": self.consistent,
            "metadata": dict(self.metadata),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=2)
