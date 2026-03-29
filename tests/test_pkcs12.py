from pathlib import Path
from pined.openssl.pkcs12 import (
    InvalidPassword,
    InvalidPKCS12File,
    extract_certificates,
)

import pytest

example = Path(__file__).parent / "assets" / "example.p12"
password = "password"


def test_success():
    with example.open("rb") as f:
        certs = extract_certificates(f.read(), password)
        assert len(certs) == 1


def test_invalid_password():
    with pytest.raises(InvalidPassword):
        with example.open("rb") as f:
            extract_certificates(f.read(), "1234")


def test_invalid_file():
    with pytest.raises(InvalidPKCS12File):
        extract_certificates(b"1234", "1234")
