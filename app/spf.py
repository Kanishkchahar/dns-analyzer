"""SPF (Sender Policy Framework) record parser and analyzer.

Parses SPF TXT records into structured data, counts DNS lookups against the
RFC 7208 limit of 10, flattens include chains into raw IP ranges, and reports
common misconfigurations.
"""

import asyncio
import re
from typing import Any

import dns.asyncresolver
import dns.exception

from app.models import Finding

# Qualifiers defined by RFC 7208 §4.6.2
_QUALIFIERS = {"+", "-", "~", "?"}

# Mechanisms that trigger a DNS lookup (RFC 7208 §4.6.4)
_LOOKUP_MECHANISMS = {"include", "a", "mx", "ptr", "exists", "redirect"}

# Maximum recursion depth to prevent abuse / infinite loops
_MAX_DEPTH = 10


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(severity: str, record_type: str, message: str) -> Finding:
    """Shorthand constructor matching the pattern in ``app.analyzer``."""
    return Finding(severity=severity, record_type=record_type, message=message)


def _parse_term(term: str) -> dict[str, str | None]:
    """Parse a single SPF term into qualifier, type, and value.

    Examples::

        "+ip4:1.2.3.0/24" -> {"qualifier": "+", "type": "ip4", "value": "1.2.3.0/24"}
        "include:_spf.google.com" -> {"qualifier": "+", "type": "include", "value": "_spf.google.com"}
        "~all" -> {"qualifier": "~", "type": "all", "value": None}
        "redirect=_spf.example.com" -> {"qualifier": "+", "type": "redirect", "value": "_spf.example.com"}
    """
    # Handle redirect=... (modifier, not a mechanism, but we model it the same)
    redirect_match = re.match(r"^redirect=(.+)$", term, re.IGNORECASE)
    if redirect_match:
        return {"qualifier": "+", "type": "redirect", "value": redirect_match.group(1)}

    # Handle exp=... (modifier)
    exp_match = re.match(r"^exp=(.+)$", term, re.IGNORECASE)
    if exp_match:
        return {"qualifier": "+", "type": "exp", "value": exp_match.group(1)}

    # Strip optional qualifier prefix
    qualifier = "+"
    if term and term[0] in _QUALIFIERS:
        qualifier = term[0]
        term = term[1:]

    # Split type:value
    if ":" in term:
        mtype, _, value = term.partition(":")
        return {"qualifier": qualifier, "type": mtype.lower(), "value": value}

    return {"qualifier": qualifier, "type": term.lower(), "value": None}


# ---------------------------------------------------------------------------
# 1. parse_spf
# ---------------------------------------------------------------------------

def parse_spf(txt_records: list[str]) -> dict[str, Any] | None:
    """Find and parse an SPF record from a list of TXT record strings.

    Parameters
    ----------
    txt_records:
        Raw TXT record strings, e.g. as returned by the resolver.

    Returns
    -------
    dict or None
        A structured SPF dict, or ``None`` if no SPF record was found.

        Keys:
        - ``raw`` – the original SPF string
        - ``version`` – always ``"spf1"``
        - ``mechanisms`` – list of parsed mechanism dicts
        - ``all_mechanism`` – the ``all`` term string (e.g. ``"-all"``), or ``None``
        - ``redirect`` – the redirect target domain, or ``None``
        - ``includes`` – list of ``include:`` target domains
    """
    spf_records = [r for r in txt_records if r.strip().lower().startswith("v=spf1")]
    if not spf_records:
        return None

    # RFC 7208 §3.2: only one SPF record is permitted per domain.  We parse
    # the first one we find; ``analyze_spf`` will flag duplicates.
    raw = spf_records[0]
    parts = raw.split()

    mechanisms: list[dict[str, str | None]] = []
    all_mechanism: str | None = None
    redirect: str | None = None
    includes: list[str] = []

    for part in parts[1:]:  # skip "v=spf1"
        parsed = _parse_term(part)
        mechanisms.append(parsed)

        if parsed["type"] == "all":
            all_mechanism = f"{parsed['qualifier']}all"
        elif parsed["type"] == "redirect":
            redirect = parsed["value"]
        elif parsed["type"] == "include" and parsed["value"]:
            includes.append(parsed["value"])

    return {
        "raw": raw,
        "version": "spf1",
        "mechanisms": mechanisms,
        "all_mechanism": all_mechanism,
        "redirect": redirect,
        "includes": includes,
    }


# ---------------------------------------------------------------------------
# 2. count_spf_lookups
# ---------------------------------------------------------------------------

async def count_spf_lookups(domain: str, resolver: dns.asyncresolver.Resolver) -> dict[str, Any]:
    """Recursively count DNS lookups triggered by an SPF record.

    Per RFC 7208 §4.6.4 the mechanisms ``include``, ``a``, ``mx``, ``ptr``,
    ``exists``, and ``redirect`` each consume one lookup.  ``ip4``, ``ip6``,
    and ``all`` do not.

    Parameters
    ----------
    domain:
        The domain whose SPF record to analyze.
    resolver:
        A ``dns.asyncresolver.Resolver`` instance.

    Returns
    -------
    dict
        ``total_lookups`` (int), ``limit`` (10), ``over_limit`` (bool),
        and ``lookup_tree`` showing the recursive chain.
    """
    tree = await _count_lookups_recursive(domain, resolver, current_path=frozenset(), depth=0)
    total = _sum_tree_lookups(tree)
    return {
        "total_lookups": total,
        "limit": 10,
        "over_limit": total > 10,
        "lookup_tree": tree,
    }


async def _count_lookups_recursive(
    domain: str,
    resolver: dns.asyncresolver.Resolver,
    current_path: frozenset[str],
    depth: int,
) -> list[dict[str, Any]]:
    """Build a lookup-tree list for *domain* up to ``_MAX_DEPTH``."""
    norm_domain = domain.lower().rstrip(".")
    if depth >= _MAX_DEPTH or norm_domain in current_path:
        return []
    new_path = current_path | {norm_domain}

    # Fetch TXT records for this domain
    try:
        answer = await resolver.resolve(domain, "TXT")
        txt_records = [b"".join(rr.strings).decode("utf-8", errors="replace") for rr in answer]
    except Exception:
        return []

    spf = parse_spf(txt_records)
    if spf is None:
        return []

    tree: list[dict[str, Any]] = []

    for mech in spf["mechanisms"]:
        mtype = mech["type"]
        if mtype not in _LOOKUP_MECHANISMS:
            continue

        value = mech["value"] or domain
        label = f"{mtype}:{value}" if mtype != "redirect" else f"redirect={value}"
        children: list[dict[str, Any]] = []

        # Recurse into includes and redirects
        if mtype in ("include", "redirect"):
            children = await _count_lookups_recursive(value, resolver, new_path, depth + 1)

        child_lookups = _sum_tree_lookups(children)
        tree.append({
            "mechanism": label,
            "lookups": 1 + child_lookups,
            "children": children,
        })

    return tree


def _sum_tree_lookups(tree: list[dict[str, Any]]) -> int:
    """Sum the ``lookups`` values at the top level of a lookup tree."""
    return sum(node["lookups"] for node in tree)


# ---------------------------------------------------------------------------
# 3. flatten_spf
# ---------------------------------------------------------------------------

async def flatten_spf(domain: str, resolver: dns.asyncresolver.Resolver) -> dict[str, Any]:
    """Resolve all include / a / mx mechanisms to static IP terms preserving semantics.

    Produces a flattened SPF record ONLY when the original policy semantics can be
    safely preserved. If the record uses non-default qualifiers on mechanisms, unsupported
    mechanisms (such as ptr or exists), dynamic macros, or lacks an explicit 'all' mechanism,
    it returns can_flatten=False and no flattened_record replacement.

    Parameters
    ----------
    domain:
        The domain whose SPF record to flatten.
    resolver:
        A ``dns.asyncresolver.Resolver`` instance.

    Returns
    -------
    dict
        ``can_flatten`` (bool), ``flattened_record`` (str | None), ``reason`` (str | None),
        ``ip4_ranges`` (list[str]), ``ip6_ranges`` (list[str]),
        ``original_lookups`` (int), and ``flattened_lookups`` (int).
    """
    try:
        lookup_data = await count_spf_lookups(domain, resolver)
        original_lookups = lookup_data.get("total_lookups", 0)
    except Exception:
        original_lookups = 0

    try:
        answer = await resolver.resolve(domain, "TXT")
        txt_records = [b"".join(rr.strings).decode("utf-8", errors="replace") for rr in answer]
    except Exception as exc:
        return {
            "can_flatten": False,
            "flattened_record": None,
            "reason": f"Unable to retrieve SPF TXT record for '{domain}': {exc}",
            "ip4_ranges": [],
            "ip6_ranges": [],
            "original_lookups": original_lookups,
            "flattened_lookups": original_lookups,
        }

    top_spf = parse_spf(txt_records)
    if top_spf is None:
        return {
            "can_flatten": False,
            "flattened_record": None,
            "reason": f"No valid SPF record found on '{domain}'.",
            "ip4_ranges": [],
            "ip6_ranges": [],
            "original_lookups": original_lookups,
            "flattened_lookups": original_lookups,
        }

    # Requirement: preserve source 'all' mechanism. If no explicit 'all' is defined,
    # defaulting to -all changes RFC neutral semantics to hard-fail rejection, which is unsafe.
    if not top_spf.get("all_mechanism"):
        return {
            "can_flatten": False,
            "flattened_record": None,
            "reason": "Cannot safely flatten: source SPF record lacks an explicit 'all' mechanism (implicit neutral policy cannot be converted without altering sender evaluation).",
            "ip4_ranges": [],
            "ip6_ranges": [],
            "original_lookups": original_lookups,
            "flattened_lookups": original_lookups,
        }

    visited: set[str] = set()
    terms: list[str] = []
    can_flatten, reason = await _flatten_terms_recursive(
        domain, resolver, visited, terms, depth=0, is_top=True
    )

    if not can_flatten:
        return {
            "can_flatten": False,
            "flattened_record": None,
            "reason": reason,
            "ip4_ranges": [],
            "ip6_ranges": [],
            "original_lookups": original_lookups,
            "flattened_lookups": original_lookups,
        }

    # Deduplicate terms in-place preserving order
    deduped_terms = list(dict.fromkeys(terms))
    ip4_ranges = [t.split(":", 1)[1] for t in deduped_terms if t.startswith("ip4:")]
    ip6_ranges = [t.split(":", 1)[1] for t in deduped_terms if t.startswith("ip6:")]

    parts = ["v=spf1"]
    parts.extend(deduped_terms)
    parts.append(top_spf["all_mechanism"])  # Preserves exact qualifier (+all, -all, ~all, ?all)
    flattened_record = " ".join(parts)

    return {
        "can_flatten": True,
        "flattened_record": flattened_record,
        "reason": None,
        "ip4_ranges": ip4_ranges,
        "ip6_ranges": ip6_ranges,
        "original_lookups": original_lookups,
        "flattened_lookups": 0,
    }


async def _flatten_terms_recursive(
    domain: str,
    resolver: dns.asyncresolver.Resolver,
    visited: set[str],
    terms: list[str],
    depth: int,
    is_top: bool = False,
) -> tuple[bool, str | None]:
    if depth >= _MAX_DEPTH:
        return False, f"Include recursion depth exceeded limit ({_MAX_DEPTH}) at '{domain}'."
    if domain in visited:
        return False, f"Circular include reference detected at '{domain}'."
    visited.add(domain)

    try:
        answer = await resolver.resolve(domain, "TXT")
        txt_records = [b"".join(rr.strings).decode("utf-8", errors="replace") for rr in answer]
    except Exception as exc:
        return False, f"Failed resolving TXT record for '{domain}': {exc}"

    spf = parse_spf(txt_records)
    if spf is None:
        return False, f"Missing or invalid SPF record in included domain '{domain}'."

    for mech in spf["mechanisms"]:
        mtype = mech["type"]
        qualifier = mech["qualifier"]
        value = mech["value"]

        if mtype == "all":
            # For top-level, all is appended at the very end.
            # For included records, RFC 7208 specifies that the included record's 'all'
            # mechanism is ignored by the calling record.
            continue

        if qualifier != "+":
            return (
                False,
                f"Cannot safely flatten '{domain}': mechanism '{qualifier}{mtype}' uses qualifier '{qualifier}'. Flattening requires positive (+) evaluation semantics to preserve policy.",
            )

        if mtype in ("ptr", "exists", "exp"):
            return (
                False,
                f"Cannot safely flatten '{domain}': unsupported dynamic mechanism '{mtype}' cannot be expanded into static IP ranges.",
            )

        if value and "%" in value:
            return (
                False,
                f"Cannot safely flatten '{domain}': dynamic macro expression in '{mtype}:{value}' cannot be expanded statically.",
            )

        if mtype == "ip4" and value:
            terms.append(f"ip4:{value}")
        elif mtype == "ip6" and value:
            terms.append(f"ip6:{value}")
        elif mtype == "a":
            target = value or domain
            a_ips, aaaa_ips = await _resolve_host_ips(target, resolver)
            for ip in a_ips:
                terms.append(f"ip4:{ip}")
            for ip in aaaa_ips:
                terms.append(f"ip6:{ip}")
        elif mtype == "mx":
            target = value or domain
            mx_a_ips, mx_aaaa_ips = await _resolve_mx_ips(target, resolver)
            for ip in mx_a_ips:
                terms.append(f"ip4:{ip}")
            for ip in mx_aaaa_ips:
                terms.append(f"ip6:{ip}")
        elif mtype in ("include", "redirect") and value:
            ok, err = await _flatten_terms_recursive(
                value, resolver, visited, terms, depth + 1, is_top=False
            )
            if not ok:
                return False, err
        else:
            return False, f"Cannot safely flatten '{domain}': unrecognized mechanism '{mtype}'."

    return True, None


async def _resolve_host_ips(
    host: str,
    resolver: dns.asyncresolver.Resolver,
) -> tuple[list[str], list[str]]:
    a_ips: list[str] = []
    aaaa_ips: list[str] = []
    try:
        answer = await resolver.resolve(host, "A")
        for rr in answer:
            a_ips.append(rr.address)
    except Exception:
        pass

    try:
        answer = await resolver.resolve(host, "AAAA")
        for rr in answer:
            aaaa_ips.append(rr.address)
    except Exception:
        pass
    return a_ips, aaaa_ips


async def _resolve_mx_ips(
    domain: str,
    resolver: dns.asyncresolver.Resolver,
) -> tuple[list[str], list[str]]:
    hosts: list[str] = []
    try:
        answer = await resolver.resolve(domain, "MX")
        hosts = [str(rr.exchange).rstrip(".") for rr in answer]
    except Exception:
        return [], []

    all_a: list[str] = []
    all_aaaa: list[str] = []
    tasks = [_resolve_host_ips(h, resolver) for h in hosts]
    results = await asyncio.gather(*tasks)
    for a_list, aaaa_list in results:
        all_a.extend(a_list)
        all_aaaa.extend(aaaa_list)
    return all_a, all_aaaa


# ---------------------------------------------------------------------------
# 4. analyze_spf
# ---------------------------------------------------------------------------

def analyze_spf(
    spf_data: dict[str, Any] | None,
    lookup_data: dict[str, Any] | None,
    *,
    txt_records: list[str] | None = None,
) -> list[Finding]:
    """Return a list of findings for common SPF misconfigurations.

    Parameters
    ----------
    spf_data:
        The output of :func:`parse_spf`, or ``None`` if no SPF record was
        found.
    lookup_data:
        The output of :func:`count_spf_lookups`, or ``None``.
    txt_records:
        The raw TXT records list — used to detect multiple SPF records.

    Returns
    -------
    list[Finding]
        Each finding has ``severity``, ``record_type``, and ``message``.
    """
    findings: list[Finding] = []

    # --- No SPF record -------------------------------------------------------
    if spf_data is None:
        findings.append(_finding(
            "error", "SPF",
            "No SPF record found. Without SPF, receiving servers cannot verify "
            "which hosts are authorized to send email for this domain.",
        ))
        return findings

    # --- Multiple SPF records (RFC 7208 §3.2) --------------------------------
    if txt_records is not None:
        spf_count = sum(1 for r in txt_records if r.strip().lower().startswith("v=spf1"))
        if spf_count > 1:
            findings.append(_finding(
                "error", "SPF",
                f"Multiple SPF records found ({spf_count}). RFC 7208 requires "
                "exactly one SPF record per domain — multiple records cause "
                "unpredictable behavior.",
            ))

    # --- Lookup limit ---------------------------------------------------------
    if lookup_data is not None:
        total = lookup_data.get("total_lookups", 0)
        if total > 10:
            findings.append(_finding(
                "error", "SPF",
                f"SPF record triggers {total} DNS lookups, exceeding the RFC 7208 "
                "limit of 10. Messages may be rejected with a PermError.",
            ))
        elif total >= 8:
            findings.append(_finding(
                "warning", "SPF",
                f"SPF record triggers {total} DNS lookups, approaching the "
                "RFC 7208 limit of 10. Adding more include/redirect mechanisms "
                "may push it over.",
            ))

    # --- all mechanism --------------------------------------------------------
    all_mech = spf_data.get("all_mechanism")
    if all_mech is None:
        findings.append(_finding(
            "warning", "SPF",
            "SPF record has no 'all' mechanism. Without it the default behavior "
            "is neutral (?all), providing no protection.",
        ))
    elif all_mech == "+all":
        findings.append(_finding(
            "error", "SPF",
            "SPF record uses '+all', which allows any server to send email as "
            "your domain. This effectively disables SPF protection.",
        ))
    elif all_mech == "?all":
        findings.append(_finding(
            "warning", "SPF",
            "SPF record uses '?all' (neutral). This provides no protection — "
            "consider using '~all' or '-all'.",
        ))
    elif all_mech == "~all":
        findings.append(_finding(
            "info", "SPF",
            "SPF record uses '~all' (softfail). Messages from unauthorized "
            "servers will be marked but not rejected. Consider upgrading to "
            "'-all' for strict enforcement.",
        ))
    elif all_mech == "-all":
        findings.append(_finding(
            "info", "SPF",
            "SPF record uses '-all' — strict policy. Unauthorized servers will "
            "have their messages rejected.",
        ))

    # --- Deprecated ptr mechanism (RFC 7208 §5.5) -----------------------------
    for mech in spf_data.get("mechanisms", []):
        if mech["type"] == "ptr":
            findings.append(_finding(
                "warning", "SPF",
                "SPF record uses the deprecated 'ptr' mechanism. RFC 7208 §5.5 "
                "strongly discourages its use due to performance and reliability "
                "concerns.",
            ))
            break  # only report once

    # --- Record length (>255 chars per TXT string) ----------------------------
    raw = spf_data.get("raw", "")
    if len(raw) > 255:
        findings.append(_finding(
            "warning", "SPF",
            f"SPF record is {len(raw)} characters long, exceeding the 255-byte "
            "limit for a single DNS TXT string. It must be split across multiple "
            "strings, which some resolvers handle incorrectly.",
        ))

    return findings
