import requests
import json
import sys
import base64
import datetime
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from pathlib import Path
from OpenSSL import crypto
import urllib3
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization.pkcs7 import load_der_pkcs7_certificates
from asn1crypto import cms
import subprocess
import hashlib
import tempfile
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===============================
# Test Case 22
# ===============================
def fetch_mud_file(mud_url, save_dir="mud_files"):
    """Retrieve MUD file from server and save locally"""
    ca_cert_path = "/home/iot/Documents/MUD/mud_ubuntu/mud-manager/mud-manager/mudtester/luminaire-cacert.pem"

    # Ensure .json extension
    if not mud_url.endswith(".json"):
        mud_url = mud_url.rstrip("/") + ".json"

    try:
        kwargs = {"timeout": 10}
        if ca_cert_path and Path(ca_cert_path).exists():
            kwargs["verify"] = ca_cert_path
        else:
            kwargs["verify"] = False  # allow expired/invalid certs

        response = requests.get(mud_url, verify=False)
        response.raise_for_status()
        mud_content = response.text

        # Create directory if it doesn't exist
        Path(save_dir).mkdir(parents=True, exist_ok=True)

        # Derive filename from URL
        filename = mud_url.rstrip("/").split("/")[-1]

        file_path = Path(save_dir) / filename
        with open(file_path, "w") as f:
            f.write(mud_content)

        return mud_content, str(file_path), True
    except requests.RequestException:
        return None, None, False

# ===============================
# Test Case 23
# ===============================
def verify_mud_signature(mud_json):
    """Check for presence and structure of digital signature (DER-encoded CMS)"""
    try:
        mud_data = json.loads(mud_json)
    except json.JSONDecodeError:
        return False

    signature_b64 = mud_data.get("mud-signature")
    if not signature_b64:
        return False

    try:
        signature_der = base64.b64decode(signature_b64)
        crypto.load_pkcs7_data(crypto.FILETYPE_ASN1, signature_der)
        return True
    except Exception:
        return False




def main():
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: tests.py <MUD_URL>"}))
        sys.exit(1)

    mud_url = sys.argv[1]

    mud_file, saved_path, retrieved_ok = fetch_mud_file(mud_url)

    signature_ok = False
    if mud_file:
        signature_ok = verify_mud_signature(mud_file)


    # Final JSON output
    result = {
        "mud_url": mud_url,
        "retrieved": retrieved_ok,
        "saved_path": saved_path if retrieved_ok else None,
        "signature_valid": signature_ok,
    }

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()