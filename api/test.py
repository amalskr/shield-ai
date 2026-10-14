"""Shield-AI test runner. Usage: python3 test.py https://<cloud-run-url>
Uses only the Python standard library. Samples live in samples.json."""
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

API_URL = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080").rstrip("/")
KEYS = ["verdict", "risk_score", "scam_type", "detected_language",
        "red_flags", "explanation", "url_checks", "latency_ms"]


def post(text):
    req = urllib.request.Request(
        f"{API_URL}/analyze",
        data=json.dumps({"text": text, "reply_language": "auto"}).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        try:
            return e.code, json.loads(body)
        except ValueError:
            return e.code, {"detail": body[:500]}


with urllib.request.urlopen(f"{API_URL}/health", timeout=30) as r:
    print(r.read().decode())

samples = json.loads(Path(__file__).with_name("samples.json").read_text(encoding="utf-8"))
passed = 0
for s in samples:
    print("=" * 60)
    print(s["name"], "|", s["text"])
    print("-" * 60)
    status, d = post(s["text"])
    if "detail" in d:
        print(f"HTTP {status} ERROR:", d["detail"])
        continue
    print(json.dumps({k: d.get(k) for k in KEYS}, ensure_ascii=False, indent=2))
    ok = d.get("verdict") == s["expect"]
    passed += ok
    print(f"{'PASS' if ok else 'FAIL'} (expected {s['expect']}, got {d.get('verdict')})")

print("=" * 60)
print(f"{passed}/{len(samples)} passed")
