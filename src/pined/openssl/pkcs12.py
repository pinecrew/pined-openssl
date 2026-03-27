from cryptography.x509 import load_pem_x509_certificates, Certificate
from ._openssl import extract_certificates as _extract_certificates
from ._openssl import InvalidPassword, InvalidPKCS12File

def extract_certificates(pkcs12: bytes, password: str) -> list[Certificate]:
    return load_pem_x509_certificates(_extract_certificates(pkcs12, password))
