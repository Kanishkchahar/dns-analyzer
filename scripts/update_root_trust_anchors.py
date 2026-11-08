"""Fetch the current IANA DNS root trust anchor set and write its provenance."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import urllib.request
import xml.etree.ElementTree as ET

URL = "https://data.iana.org/root-anchors/root-anchors.xml"
DESTINATION = Path(__file__).parents[1] / "app" / "data" / "root_trust_anchors.json"


def main() -> None:
    request = urllib.request.Request(URL, headers={"User-Agent": "DNSAnalyzer trust-anchor updater"})
    with urllib.request.urlopen(request, timeout=15) as response:
        xml = response.read(1024 * 1024 + 1)
    if len(xml) > 1024 * 1024:
        raise SystemExit("IANA trust-anchor XML exceeded the 1 MiB safety limit")
    root = ET.fromstring(xml)
    anchors = []
    for entry in root.findall("KeyDigest"):
        anchors.append({
            "id": entry.get("id"),
            "key_tag": int(entry.findtext("KeyTag")),
            "algorithm": int(entry.findtext("Algorithm")),
            "digest_type": int(entry.findtext("DigestType")),
            "digest": entry.findtext("Digest"),
            "public_key": entry.findtext("PublicKey"),
            "validFrom": entry.get("validFrom"),
            "validUntil": entry.get("validUntil"),
            "revoked": False,
        })
    payload = {"source_url": URL, "retrieved_utc": datetime.now(timezone.utc).date().isoformat(),
               "xml_sha256": hashlib.sha256(xml).hexdigest(), "anchors": anchors}
    DESTINATION.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(anchors)} anchors to {DESTINATION}; XML SHA-256 {payload['xml_sha256']}")


if __name__ == "__main__":
    main()
