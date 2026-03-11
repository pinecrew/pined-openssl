from cryptography.x509 import load_pem_x509_certificates, Certificate
from .native import load_certificates as _load_certificates

def load_certificates(pkcs12: bytes, password: str) -> list[Certificate]:
    return load_pem_x509_certificates(_load_certificates(pkcs12, password))
