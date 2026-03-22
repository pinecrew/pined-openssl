from .pkcs12 import extract_certificates
from pathlib import Path
from argparse import ArgumentParser

if __name__ == "__main__":
    parser = ArgumentParser(prog="pined.openssl")
    parser.add_argument("pkcs12", type=Path)
    parser.add_argument("password", type=str)
    args = parser.parse_args()
    with args.pkcs12.open("rb") as f:
        certificates = extract_certificates(f.read(), args.password)
        for c in certificates:
            print(c)
