from argparse import ArgumentParser
from pathlib import Path
from typing import cast

from .pkcs12 import extract_certificates

if __name__ == "__main__":
    parser = ArgumentParser(prog="pined.openssl")
    parser.add_argument("pkcs12", type=Path)
    parser.add_argument("password", type=str)
    args = parser.parse_args()
    pkcs12_path = cast("Path", args.pkcs12)
    pkcs12_password = cast("str", args.password)
    with pkcs12_path.open("rb") as f:
        certificates = extract_certificates(f.read(), pkcs12_password)
        for c in certificates:
            print(c)  # noqa: T201
