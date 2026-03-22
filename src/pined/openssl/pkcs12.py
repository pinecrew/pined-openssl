from cryptography.x509 import load_pem_x509_certificates, Certificate
from .native import extract_certificates as _extract_certificates

def extract_certificates(pkcs12: bytes, password: str) -> list[Certificate]:
    return load_pem_x509_certificates(_extract_certificates(pkcs12, password))
