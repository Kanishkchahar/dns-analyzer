"""Built-in routing, DANE/TLSA, and SMTP STARTTLS scan plugin."""

from app.extended_checks import check_extended_security


def register(register_check):
    register_check("extended_security", check_extended_security,
                   "RPKI, DANE/TLSA, and SMTP STARTTLS checks")
