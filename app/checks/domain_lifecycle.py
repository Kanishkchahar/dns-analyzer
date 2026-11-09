"""Built-in RDAP registration-expiry scan plugin."""

from app.domain_lifecycle import check_domain_lifecycle


def register(register_check):
    register_check("domain_lifecycle", check_domain_lifecycle,
                   "RDAP domain registration and expiry check")
