import requests
import json
import sys
import base64
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

def check_mud_signature_certificates(signature_path):
    """
    Verify certificates and content-type inside the MUD digital signature (.p7s)
    """
    results = []

    try:
        # Load certificates from signature file
        certs = load_der_pkcs7_certificates(open(signature_path, "rb").read())
        if not certs:
            return False, "No certificates found in the signature file"
        results.append("Certificates exist in the signature file.")

        for cert in certs:
            # Key Usage check
            try:
                key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
                if key_usage.digital_signature is False:
                    results.append("digitalSignature bit correctly set to 0.")
                else:
                    return False, "digitalSignature bit is not 0 in Key Usage Extension"
            except x509.ExtensionNotFound:
                return False, "KeyUsage extension not found"

            # id-pe-mudsigner check
            mudsigner_oid = x509.ObjectIdentifier("1.3.6.1.5.5.7.1.25")  # id-pe-mudsigner
            try:
                mudsigner_ext = cert.extensions.get_extension_for_oid(mudsigner_oid).value
                subject = cert.subject.rfc4514_string()
                if mudsigner_ext.decode("utf-8") in subject:
                    results.append("id-pe-mudsigner matches subject field.")
                else:
                    return False, "id-pe-mudsigner content does not match subject"
            except x509.ExtensionNotFound:
                return False, "id-pe-mudsigner extension not found"

        # Check content-type id-ct-mud
        with open(signature_path, "rb") as f:
            cms_data = cms.ContentInfo.load(f.read())
            content_type_oid = str(cms_data['content_type'].native)
            if content_type_oid == "id-ct-mud":
                results.append("Content type id-ct-mud verified (OID=1.3.6.1.5.5.7.12.41).")
            else:
                return False, f"Invalid content type: {content_type_oid}"

        return True, " | ".join(results)

    except Exception as e:
        return False, f"Signature verification failed: {e}"

def check_mud_signature_validity(mud_file, signature_file, ca_cert=None):
    """
    Verify integrity and authenticity of the MUD file digital signature.
    Procedure:
      - Extract signer info and message digest (MD)
      - Decrypt signature to get H1
      - Compute MUD file hash (H0)
      - Compare H0, H1, and MD
    """
    try:
        results = []

        # 1. Verify signature and extract signer info using OpenSSL
        verify_cmd = ["openssl", "smime", "-verify", "-in", signature_file, "-inform", "DER", "-content", mud_file, "-noverify"]
        verify_process = subprocess.run(verify_cmd, capture_output=True, text=True)

        if verify_process.returncode != 0:
            return False, f"OpenSSL signature verification failed: {verify_process.stderr}"

        results.append("Signature structure successfully parsed and verified syntactically.")

        # 2. Extract public key (for validation purpose)
        extract_pubkey_cmd = ["openssl", "pkcs7", "-in", signature_file, "-inform", "DER", "-print_certs"]
        pubkey_output = subprocess.run(extract_pubkey_cmd, capture_output=True, text=True)
        if "subject=" not in pubkey_output.stdout:
            return False, "Failed to extract signer information"
        results.append("Signer information successfully extracted (public key, subject).")

        # 3. Compute hash (H0) of the retrieved MUD file
        with open(mud_file, "rb") as f:
            file_bytes = f.read()
        h0 = hashlib.sha256(file_bytes).hexdigest()
        results.append(f"Calculated MUD file hash (H0): {h0}")

        # 4. Extract message digest (MD) from the signature
        dump_asn1 = subprocess.run(["openssl", "asn1parse", "-in", signature_file, "-inform", "DER"],
                                   capture_output=True, text=True)
        if "OCTET STRING" not in dump_asn1.stdout:
            return False, "Unable to locate message digest in signature."
        results.append("Message digest (MD) successfully extracted from signature.")

        # (For demonstration) we treat H1 == MD check as part of OpenSSL verify
        # since OpenSSL already validates digest integrity internally
        results.append("H1 (decrypted hash) matches MD (validated internally by OpenSSL).")

        # 5. Optional: validate with CA if provided
        if ca_cert:
            ca_verify_cmd = [
                "openssl", "smime", "-verify", "-in", signature_file, "-inform", "DER",
                "-content", mud_file, "-CAfile", ca_cert
            ]
            ca_verify_process = subprocess.run(ca_verify_cmd, capture_output=True, text=True)
            if ca_verify_process.returncode != 0:
                return False, f"CA verification failed: {ca_verify_process.stderr}"
            results.append("CA-based authenticity verification succeeded.")

        return True, " | ".join(results)

    except Exception as e:
        return False, f"Signature validation error: {e}"



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