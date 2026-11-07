"""Provider-aware DNS record labels and CLI drafts for remediation suggestions."""

from __future__ import annotations

import shlex
from typing import Any


def _txt_chunks(value: str, maximum: int = 255) -> list[str]:
    """Split UTF-8 TXT data on character boundaries into <=255-byte strings."""
    chunks: list[str] = []
    current = ""
    size = 0
    for char in value:
        encoded_size = len(char.encode("utf-8"))
        if size + encoded_size > maximum and current:
            chunks.append(current)
            current, size = "", 0
        current += char
        size += encoded_size
    if current or not chunks:
        chunks.append(current)
    return chunks


def _quote_txt(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def apply_provider_templates(domain: str, fix: Any) -> None:
    """Attach provider-specific host labels and cautious command-line examples."""
    if fix.record_type != "TXT":
        return
    domain = domain.lower().rstrip(".")
    host = fix.host.strip().rstrip(".")
    is_apex = host in ("", "@", domain)
    relative = "@" if is_apex else host
    fqdn = f"{domain}." if is_apex else f"{host}.{domain}."
    ttl = int(fix.ttl)
    value = str(fix.value)
    chunks = _txt_chunks(value)
    rdata = " ".join(_quote_txt(chunk) for chunk in chunks)

    guides = dict(fix.provider_guides or {})
    guides.update({
        "Namecheap": f"Advanced DNS → Add TXT Record. Host: {relative}. Keep only the relative label; do not append {domain}. Value: paste the complete TXT value. Namecheap documents @ for the zone apex.",
        "Hostinger": f"DNS Zone Editor → TXT. Name: {relative}. Value: paste the complete TXT value. Hostinger documents @ for the apex and the relative subdomain label for child names.",
        "BigRock": f"DNS Service → Manage DNS → Add TXT. Host/Name: {relative}. Use the zone-relative host label and enter the complete value; confirm the provider's apex convention in the active DNS editor.",
        "Google Cloud DNS": f"Create or safely update a TXT RRset named {fqdn} in the managed zone. Keep existing TXT values in the RRset when they serve other verification purposes. TXT wire chunks (if required): {rdata}",
        "Azure DNS": f"Create or update a TXT record set named {relative} in zone {domain}. Keep existing TXT values. For long values, preserve the displayed TXT string chunks: {rdata}",
        "TXT wire chunks": rdata,
    })
    commands = dict(getattr(fix, "provider_commands", {}) or {})
    commands["Google Cloud DNS"] = (
        f"gcloud dns record-sets create {shlex.quote(fqdn)} "
        f"--rrdatas={shlex.quote(rdata)} --ttl={ttl} --type=TXT --zone=YOUR_MANAGED_ZONE "
        "# Create only when this TXT RRset does not already exist; otherwise merge values carefully."
    )
    if len(value.encode("utf-8")) <= 255:
        commands["Azure DNS"] = (
            "az network dns record-set txt add-record "
            "--resource-group YOUR_RESOURCE_GROUP "
            f"--zone-name {shlex.quote(domain)} --record-set-name {shlex.quote(relative)} "
            f"--value {shlex.quote(value)}"
        )
    else:
        commands["Azure DNS"] = "Long TXT value: use Azure DNS portal/API to preserve the TXT string chunks shown above; do not create separate records for each chunk."
    fix.provider_guides = guides
    fix.provider_commands = commands
