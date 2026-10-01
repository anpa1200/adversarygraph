"""Check committed synthetic expectations; no application, network or LLM calls."""
import json
from pathlib import Path
root = Path(__file__).resolve().parent
report = (root / "sample-report.md").read_text().replace("`", "")
techniques = json.loads((root / "expected-techniques.json").read_text())["expected"]
iocs = json.loads((root / "expected-iocs.json").read_text())
layer = json.loads((root / "expected-navigator-layer.json").read_text())
assert {x["attack_id"] for x in techniques} == {x["techniqueID"] for x in layer["techniques"]}
assert all(x["evidence"] in report for x in techniques)
assert all(value in report for values in iocs.values() for value in values)
graph = json.loads((root / "evidence-graph/expected-graph.json").read_text())
types = {x["node_type"] for x in graph["nodes"]}
assert all(a in types and b in types for _, a, b in graph["edges"])
print(f"PASS: {len(techniques)} technique expectations, {sum(map(len, iocs.values()))} IOC expectations, {len(graph['edges'])} graph edges")
print("Scope: fixture consistency only; no application extraction, SIEM replay or AI accuracy claim")
