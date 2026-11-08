"""Fetch the current IANA DNS root trust anchor set and write its provenance."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import tempfile
import urllib.request

from defusedxml import ElementTree as ET

URL = "https://data.iana.org/root-anchors/root-anchors.xml"
SIGNATURE_URL = "https://data.iana.org/root-anchors/root-anchors.p7s"
CERTIFICATE_BUNDLE_URL = "https://data.iana.org/root-anchors/icannbundle.pem"
DESTINATION = Path(__file__).parents[1] / "app" / "data" / "root_trust_anchors.json"


def _download(url: str, cap: int = 1024 * 1024) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "DNSAnalyzer trust-anchor updater"})
    with urllib.request.urlopen(request, timeout=15) as response:
        payload = response.read(cap + 1)
    if len(payload) > cap:
        raise ValueError(f"IANA resource exceeded the {cap}-byte safety limit")
    return payload


def verify_detached_signature(xml: bytes, signature: bytes, certificate_bundle: bytes) -> None:
    """Verify the detached CMS/S-MIME signature using IANA's published CA bundle."""
    with tempfile.TemporaryDirectory(prefix="dns-analyzer-anchor-") as temporary:
        root = Path(temporary)
        xml_path, signature_path, ca_path = root / "root-anchors.xml", root / "root-anchors.p7s", root / "icannbundle.pem"
        xml_path.write_bytes(xml)
        signature_path.write_bytes(signature)
        ca_path.write_bytes(certificate_bundle)
        subprocess.run(
            ["openssl", "smime", "-verify", "-inform", "DER", "-in", str(signature_path),
             "-content", str(xml_path), "-CAfile", str(ca_path), "-out", str(root / "verified.xml")],
            check=True, capture_output=True, text=True,
        )


def build_anchor_document(xml: bytes, retrieved_utc: str) -> dict:
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
    return {"source_url": URL, "retrieved_utc": retrieved_utc,
            "xml_sha256": hashlib.sha256(xml).hexdigest(),
            "signature_verification": {"verified": True, "signature_url": SIGNATURE_URL,
                "certificate_bundle_url": CERTIFICATE_BUNDLE_URL,
                "method": "openssl smime -verify -inform DER", "certificate_subject": "O=ICANN, OU=ICANN Certification Authority, CN=ICANN Root CA, C=US"},
            "anchors": anchors}


def main() -> None:
    xml = _download(URL)
    signature = _download(SIGNATURE_URL)
    certificate_bundle = _download(CERTIFICATE_BUNDLE_URL)
    verify_detached_signature(xml, signature, certificate_bundle)
    payload = build_anchor_document(xml, datetime.now(timezone.utc).date().isoformat())
    DESTINATION.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(payload['anchors'])} verified anchors to {DESTINATION}; XML SHA-256 {payload['xml_sha256']}")


if __name__ == "__main__":
    main()
