from pathlib import Path

import pytest

from pined.openssl.pkcs12 import (
    InvalidPassword,
    InvalidPKCS12File,
    extract_certificates,
)

example = Path(__file__).parent / "assets" / "example.p12"
password = "password"


def test_success() -> None:
    with example.open("rb") as f:
        certs = extract_certificates(f.read(), password)
        assert len(certs) == 1


def test_invalid_password() -> None:
    with pytest.raises(InvalidPassword), example.open("rb") as f:
        extract_certificates(f.read(), "1234")


def test_invalid_file() -> None:
    with pytest.raises(InvalidPKCS12File):
        extract_certificates(b"1234", "1234")
