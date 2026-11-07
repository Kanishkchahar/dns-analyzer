from app.models import RemediationFix
from app.provider_templates import _txt_chunks, apply_provider_templates


def test_txt_chunking_obeys_dns_255_octet_limit():
    chunks = _txt_chunks("a" * 254 + "é" + "b")

    assert [len(chunk.encode("utf-8")) for chunk in chunks] == [254, 3]
    assert "".join(chunks) == "a" * 254 + "é" + "b"


def test_provider_templates_use_zone_relative_names_and_commands():
    fix = RemediationFix(title="DMARC", record_type="TXT", host="_dmarc", value="v=DMARC1; p=none")

    apply_provider_templates("example.com", fix)

    assert "Host: _dmarc" in fix.provider_guides["Namecheap"]
    assert "Name: _dmarc" in fix.provider_guides["Hostinger"]
    assert "_dmarc.example.com." in fix.provider_commands["Google Cloud DNS"]
    assert "--record-set-name _dmarc" in fix.provider_commands["Azure DNS"]
    assert fix.provider_guides["TXT wire chunks"] == '"v=DMARC1; p=none"'


def test_provider_templates_do_not_add_txt_commands_to_dnssec_fixes():
    fix = RemediationFix(title="DNSSEC", record_type="DS", host="@", value="Enable DNSSEC")

    apply_provider_templates("example.com", fix)

    assert fix.provider_commands == {}
