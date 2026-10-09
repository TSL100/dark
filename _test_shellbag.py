import collections
import sys

sys.path.insert(0, r"C:\Users\MOHAMED\Desktop\CyberSecurity\Defense\PoC")
from tier1_artifacts import AcquisitionEngine, available

ok, reason = available().get("shellbag", (False, "missing"))
print("available:", ok, reason)
if not ok:
    raise SystemExit(1)

eng = AcquisitionEngine(None, None)
recs, report = eng.run(["shellbag"])
print("report:", report)
print("records:", len(recs))

roots = collections.Counter(r["details"].get("root", "?")[-40:] for r in recs)
print("roots:", dict(roots))
ts_src = collections.Counter(r["details"].get("timestamp_source") for r in recs)
print("timestamp_source:", dict(ts_src))
names = collections.Counter(r["artifact_name"] for r in recs)
print("top names:", names.most_common(15))
q = [r for r in recs if r["artifact_name"] in ("?", "", None)]
print("unknown-name entries:", len(q))
missing_ts = [r for r in recs if not r["timestamp"]]
print("missing timestamp:", len(missing_ts))
bad_path = [r for r in recs if not r["target_path"] or r["target_path"].startswith("\\")]
print("bad paths:", len(bad_path))

print("--- samples ---")
for r in recs[:12]:
    print(r["timestamp"], "|", r["target_path"], "|", r["artifact_name"],
          "|", r["details"]["timestamp_source"], "| slot", r["details"].get("bag_slot"))
print("--- deep paths (max depth) ---")
deep = sorted(recs, key=lambda r: r["target_path"].count("\\"), reverse=True)[:8]
for r in deep:
    print(r["timestamp"], "|", r["target_path"])

schema = ["timestamp_utc", "timestamp", "source", "artifact_type",
          "artifact_name", "target_path", "source_hash", "details"]
missing = [k for k in schema if any(k not in r for r in recs)]
print("schema keys missing:", missing or "none")
bad_ts = [r for r in recs if not str(r["timestamp_utc"]).startswith("2")]
print("non-ISO timestamps:", len(bad_ts))
