from cryptography.x509 import Certificate, load_pem_x509_certificates

from ._openssl import InvalidPassword, InvalidPKCS12File
from ._openssl import extract_certificates as _extract_certificates


def extract_certificates(pkcs12: bytes, password: str) -> list[Certificate]:
    return load_pem_x509_certificates(_extract_certificates(pkcs12, password))


__all__ = ["InvalidPKCS12File", "InvalidPassword", "extract_certificates"]
