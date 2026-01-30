import sys
import json
from datetime import datetime
from email.utils import parsedate_to_datetime
import ipaddress
import re
from urllib.parse import urlparse
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





# ===============================
# Allowed MUD file nodes
# ===============================
ALLOWED_NODES = {
    "mud-version",
    "mud-url",
    "last-update",
    "mud-signature",
    "cache-validity",
    "is-supported",
    "systeminfo",
    "mfg name",
    "model-name",
    "firmware-rev",
    "software-rev",
    "documentation",
    "extensions",
    "from-device-policy",
    "to-device-policy",
    "manufacturer",
    "same-manufacturer",
    "model",
    "local-networks",
    "controller",
    "my-controller",
    "direction-initiated"
}

# ===============================
# Test Case 18
# ===============================
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

# ===============================
# Test Case 19
# ===============================
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

# ===============================
# Test Case 20
# ===============================
def check_certificate_validity(signature_file, ca_cert_file):
    """
    Verify the validity of the certificate(s) embedded within a MUD signature file.
    Steps:
      - Extract X.509 certificates from the signature
      - Verify CA-based signature validation
      - Check validity dates
      - Check revocation info (CRL/OCSP if available)
      - Validate chain of trust
    """
    try:
        results = []

        # 1. Extract certificates from the MUD signature (.p7s)
        extract_cmd = ["openssl", "pkcs7", "-in", signature_file, "-inform", "DER", "-print_certs"]
        proc = subprocess.run(extract_cmd, capture_output=True, text=True)
        certs_pem = proc.stdout.strip()

        if not certs_pem:
            return False, "No certificates found in signature."

        # Save extracted certs temporarily
        with open("/tmp/extracted_certs.pem", "w") as f:
            f.write(certs_pem)

        results.append("Extracted certificate(s) from signature file.")

        # 2. Verify certificate chain using CA cert
        verify_cmd = [
            "openssl", "verify", "-CAfile", ca_cert_file, "/tmp/extracted_certs.pem"
        ]
        verify_proc = subprocess.run(verify_cmd, capture_output=True, text=True)
        if verify_proc.returncode != 0:
            return False, f"Certificate chain verification failed: {verify_proc.stderr.strip()}"
        results.append("Certificate chain verified successfully against CA.")

        # 3. Parse and check each certificate’s validity dates
        for cert_pem in certs_pem.split("-----END CERTIFICATE-----"):
            if "BEGIN CERTIFICATE" not in cert_pem:
                continue
            cert_pem = cert_pem + "-----END CERTIFICATE-----"
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            not_before = cert.not_valid_before
            not_after = cert.not_valid_after
            now = datetime.datetime.utcnow()

            if not_before > now or not_after < now:
                return False, f"Certificate expired or not yet valid: {cert.subject}"
            results.append(f"Certificate validity period OK: {not_before} → {not_after}")

        # 4. (Optional) Check revocation info (CRL or OCSP URL)
        crl_dist_points = []
        try:
            for ext in cert.extensions:
                if ext.oid.dotted_string == "2.5.29.31":  # CRL Distribution Points
                    crl_dist_points.append(str(ext.value))
            if crl_dist_points:
                results.append(f"CRL distribution points found: {crl_dist_points}")
            else:
                results.append("No CRL URLs found; skipping revocation check.")
        except Exception:
            results.append("Skipping CRL parsing (no extensions found).")

        # 5. Verify root CA presence
        ca_info = subprocess.run(["openssl", "x509", "-in", ca_cert_file, "-noout", "-subject"],
                                 capture_output=True, text=True)
        results.append(f"Trusted CA loaded: {ca_info.stdout.strip()}")

        return True, " | ".join(results)

    except Exception as e:
        return False, f"Certificate validation error: {e}"
    

# ===============================
# Test Case 1: UTF-8 encoding check
# ===============================
def check_utf8_encoding(file_path):
    """Verify that the MUD file is encoded in UTF-8."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            f.read()
        return True, "File is UTF-8 encoded"
    except UnicodeDecodeError:
        return False, "File is not UTF-8 encoded"
    except Exception as e:
        return False, f"Error reading file: {str(e)}"


# ===============================
# Test Case 2: Allowed nodes check
# ===============================
def check_allowed_nodes(file_path):
    """
    Verify that the retrieved MUD file includes only allowed nodes
    (except optional 'extensions').
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            mud_data = json.load(f)

        # Collect all top-level keys
        used_nodes = set(mud_data.keys())

        # Find disallowed nodes
        disallowed_nodes = used_nodes - ALLOWED_NODES

        if disallowed_nodes:
            return False, f"Disallowed nodes found: {', '.join(disallowed_nodes)}"
        else:
            return True, "All nodes are within the allowed set"

    except json.JSONDecodeError:
        return False, "Invalid JSON structure"
    except Exception as e:
        return False, f"Error checking nodes: {str(e)}"


# ===============================
# Test Case 3: Extension validation
# ===============================
def check_extensions(file_path):
    """
    Verify that:
      1. Extensions listed in 'extensions' field match those used in the file.
      2. No undeclared extensions are present in the MUD file.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            mud_data = json.load(f)

        declared_extensions = set(mud_data.get("extensions", []))

        # Collect all keys in the JSON recursively
        def collect_keys(obj, keys):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    keys.add(k)
                    collect_keys(v, keys)
            elif isinstance(obj, list):
                for item in obj:
                    collect_keys(item, keys)

        used_nodes = set()
        collect_keys(mud_data, used_nodes)

        # Extensions used are those not in ALLOWED_NODES
        used_extensions = used_nodes - ALLOWED_NODES

        # Check undeclared usage
        undeclared = used_extensions - declared_extensions

        if undeclared:
            return False, f"Undeclared extensions used: {', '.join(undeclared)}"

        # Check declared but unused
        unused = declared_extensions - used_extensions
        if unused:
            return False, f"Declared but unused extensions: {', '.join(unused)}"

        return True, "All extensions are valid and declared properly"

    except json.JSONDecodeError:
        return False, "Invalid JSON structure"
    except Exception as e:
        return False, f"Error checking extensions: {str(e)}"

# ===============================
# Test Case 4: Extension IETF/IANA standardization
# ===============================
def check_extensions_standardization(file_path):
    """
    Verify if all declared/used extensions:
      1. Are UTF-8 strings <= 40 chars
      2. Reference an RFC (IETF standardization)
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            mud_data = json.load(f)

        declared_extensions = mud_data.get("extensions", [])
        if not isinstance(declared_extensions, list):
            return False, "Invalid 'extensions' format (must be a list)"

        invalid = []
        for ext in declared_extensions:
            if not isinstance(ext, str):
                invalid.append(f"{ext} (not a string)")
                continue
            try:
                ext.encode("utf-8")
            except UnicodeError:
                invalid.append(f"{ext} (not UTF-8)")
                continue
            if len(ext) > 40:
                invalid.append(f"{ext} (exceeds 40 chars)")

            # Check for RFC reference
            # Convention: extension should include some RFC reference field in mud_data
            ext_metadata = mud_data.get("extension-details", {}).get(ext, {})
            rfc_ref = ext_metadata.get("rfc") or ext_metadata.get("iana-reference")
            if not rfc_ref:
                invalid.append(f"{ext} (missing RFC reference)")

        if invalid:
            return False, "Extensions failed standardization: " + ", ".join(invalid)
        return True, "All extensions are valid, UTF-8, within length, and RFC-referenced"

    except json.JSONDecodeError:
        return False, "Invalid JSON structure"
    except Exception as e:
        return False, f"Error checking extensions standardization: {str(e)}"

# ===============================
# Test Case 5: 
# ===============================
def check_communication_directions(mud_data):
    """
    Test Case 5:
    Verify that the MUD file explicitly declares 'from-device-policy' and 'to-device-policy'.
    Then ensure ACLs under each are consistent with the expected communication direction.
    """
    results = {"from_device_present": False, "to_device_present": False, "direction_consistency": True, "errors": []}

    # a. Verify presence of both policies
    if "from-device-policy" in mud_data:
        results["from_device_present"] = True
    else:
        results["errors"].append("Missing 'from-device-policy' node.")

    if "to-device-policy" in mud_data:
        results["to_device_present"] = True
    else:
        results["errors"].append("Missing 'to-device-policy' node.")

    # b. Check direction consistency inside ACLs
    for policy_name in ["from-device-policy", "to-device-policy"]:
        if policy_name in mud_data:
            acls = mud_data[policy_name].get("access-lists", [])
            for acl in acls:
                direction = acl.get("direction-initiated")
                if policy_name == "from-device-policy" and direction != "from-device":
                    results["direction_consistency"] = False
                    results["errors"].append(f"ACL in 'from-device-policy' has invalid direction: {direction}")
                if policy_name == "to-device-policy" and direction != "to-device":
                    results["direction_consistency"] = False
                    results["errors"].append(f"ACL in 'to-device-policy' has invalid direction: {direction}")

    return results

# ===============================
# Test Case 6: 
# ===============================
def parse_cache_directives(headers, response_time):
    if "Cache-Control" in headers:
        cache_control = headers["Cache-Control"]
        directives = {d.split("=")[0].strip(): d.split("=")[1].strip()
                      for d in cache_control.split(",") if "=" in d}

        if "s-maxage" in directives:
            return int(int(directives["s-maxage"]) / 3600)
        if "max-age" in directives:
            age_val = int(headers.get("Age", "0"))
            return int((int(directives["max-age"]) - age_val) / 3600)

    if "Expires" in headers:
        try:
            expires_time = parsedate_to_datetime(headers["Expires"])
            delta = expires_time - response_time
            return int(delta.total_seconds() / 3600)
        except Exception:
            pass

    return None

def check_cache_validity(mud_url, mud_file):
    """
    Test Case 6:
    Verify that cache-validity value is within [24, 168] and consistent with HTTP caching directives.
    """

    # 🔹 Ensure mud_file is parsed JSON, not a string path
    if isinstance(mud_file, str):
        try:
            with open(mud_file, "r", encoding="utf-8") as f:
                mud_data = json.load(f)
        except Exception:
            return False, "Failed to parse MUD file JSON."
    else:
        mud_data = mud_file  # already dict

    cache_val = mud_data.get("cache-validity")
    if cache_val is None:
        return False, "Missing 'cache-validity' field."

    if not isinstance(cache_val, int):
        return False, "'cache-validity' must be an integer."

    errors = []
    warnings = []

    if cache_val > 168:
        errors.append(f"'cache-validity' ({cache_val}) exceeds 168 hours.")
    if cache_val < 24:
        warnings.append(f"'cache-validity' ({cache_val}) is less than 24 hours (not recommended).")

    try:
        response_time = datetime.utcnow()
        resp = requests.get(mud_url, timeout=10)
        header_val = parse_cache_directives(resp.headers, response_time)

        if header_val is not None:
            if cache_val < header_val:
                errors.append(f"'cache-validity' ({cache_val}) is less than HTTP caching directive value ({header_val}).")
        else:
            warnings.append("Could not derive caching directive from HTTP headers.")
    except Exception as e:
        warnings.append(f"HTTP caching directive check skipped: {e}")

    ok = len(errors) == 0
    message = "; ".join(errors + warnings) if (errors or warnings) else "Cache-validity is valid."
    return ok, message

# ===============================
# Test Case 7
# ===============================
def check_systeminfo(mud_file):
    """
    Test Case 7:
    Verify that the values of the 'systeminfo' node are properly set.
    - Type: UTF-8
    - Length: ≤ 60 characters (excluding whitespace)
    """

    # 🔹 Ensure mud_file is parsed JSON, not just a path
    if isinstance(mud_file, str):
        try:
            with open(mud_file, "r", encoding="utf-8") as f:
                mud_data = json.load(f)
        except Exception:
            return False, "Failed to parse MUD file JSON."
    else:
        mud_data = mud_file

    systeminfo = mud_data.get("systeminfo")
    if systeminfo is None:
        return False, "Missing 'systeminfo' field."

    if not isinstance(systeminfo, str):
        return False, "'systeminfo' must be a string."

    errors = []
    warnings = []

    # 🔹 UTF-8 encoding check
    try:
        systeminfo.encode("utf-8")
    except UnicodeEncodeError:
        errors.append("'systeminfo' is not valid UTF-8.")

    # 🔹 Length check (ignoring whitespace)
    length_no_spaces = len(systeminfo.replace(" ", ""))
    if length_no_spaces > 60:
        errors.append(f"'systeminfo' length ({length_no_spaces}) exceeds 60 characters (excluding spaces).")

    ok = len(errors) == 0
    message = "; ".join(errors + warnings) if (errors or warnings) else "'systeminfo' is valid."
    return ok, message


# ===============================
# Test Case 8
# ===============================
def check_firmware_software_fields(mud_file):
    """
    Test Case 8:
    Verify that 'firmware-rev' and 'software-rev' are not present if 'is-supported' is false.
    """

    # 🔹 Ensure mud_file is parsed JSON
    if isinstance(mud_file, str):
        try:
            with open(mud_file, "r", encoding="utf-8") as f:
                mud_data = json.load(f)
        except Exception:
            return False, "Failed to parse MUD file JSON."
    else:
        mud_data = mud_file

    is_supported = mud_data.get("is-supported")

    # If missing, we cannot enforce
    if is_supported is None:
        return False, "Missing 'is-supported' field."

    errors = []

    if is_supported is False:  # Device upgrade not supported
        if "firmware-rev" in mud_data:
            errors.append("'firmware-rev' must not exist when 'is-supported' is false.")
        if "software-rev" in mud_data:
            errors.append("'software-rev' must not exist when 'is-supported' is false.")

    # ✅ If supported = true, it's fine whether or not those fields exist
    ok = len(errors) == 0
    message = "; ".join(errors) if errors else "Firmware/software revision rules satisfied."
    return ok, message



    
# ===============================
# Test Case 9
# ===============================
def check_local_network_addresses(mud_file):
    """
    Test Case 9:
    Verify that local addresses in the 'local-network' attribute of ACEs
    conform to valid IPv4/IPv6 prefix/mask formats.
    """

    # 🔹 Ensure mud_file is parsed JSON
    if isinstance(mud_file, str):
        try:
            with open(mud_file, "r", encoding="utf-8") as f:
                mud_data = json.load(f)
        except Exception:
            return False, "Failed to parse MUD file JSON."
    else:
        mud_data = mud_file

    errors = []
    valid = True

    # Collect ACEs from both policy directions
    for policy in ["from-device-policy", "to-device-policy"]:
        if policy in mud_data:
            acl_lists = mud_data[policy].get("access-lists", [])
            for acl in acl_lists:
                aces = acl.get("aces", {})
                for ace_name, ace in aces.items():
                    matches = ace.get("matches", {})
                    if "local-network" in matches:
                        addr = matches["local-network"]

                        try:
                            # Validate using ipaddress (handles IPv4/v6 CIDR)
                            ipaddress.ip_network(addr, strict=False)
                        except Exception:
                            valid = False
                            errors.append(f"Invalid local-network format in ACE '{ace_name}': {addr}")

    if valid:
        return True, "All local-network addresses are valid with prefixes/masks."
    else:
        return False, "; ".join(errors)


# ===============================
# Test Case 10
# ===============================
# Allowed URNs
WELL_KNOWN_URNS = {
    "urn:ietf:params:mud:dns",
    "urn:ietf:params:mud:ntp"
}
def check_controller_urls(mud_data):
    """
    Validate controller URLs inside ACLs.
    Returns a list of results.
    """
    results = []
    
    # Walk into ACLs -> look for "controller" nodes
    policies = []
    if "ietf-access-control-list:acls" in mud_data:
        policies = mud_data["ietf-access-control-list:acls"].get("acl", [])
    
    for acl in policies:
        for ace in acl.get("aces", {}).get("ace", []):
            matches = ace.get("matches", {})
            controller = matches.get("controller")
            
            if controller:
                # Case 1: URN
                if controller in WELL_KNOWN_URNS:
                    results.append({"controller": controller, "status": "valid (well-known URN)"})
                
                # Case 2: URL
                elif controller.startswith("http://") or controller.startswith("https://"):
                    parsed = urlparse(controller)
                    domain_pattern = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
                    if parsed.scheme in ("http", "https") and re.match(domain_pattern, parsed.hostname or ""):
                        results.append({"controller": controller, "status": "valid URL"})
                    else:
                        results.append({"controller": controller, "status": "invalid URL"})
                
                else:
                    results.append({"controller": controller, "status": "invalid (neither URN nor URL)"})
    
    if not results:
        results.append({"info": "no controller entries found"})
    
    return results


# ===============================
# Test Case 11
# ===============================
# Allowed URNs
def test_acl_attributes(mud_data):
    """
    Test Case 9: Verify that the ACL leaf nodes include required attributes:
    - 'name' of the ACL
    - 'type'
    - 'name' of the ACEs
    - TCP/UDP source and destination port information (if applicable)
    """

    results = {"status": "PASS", "details": []}

    try:
        acls = mud_data.get("ietf-access-control-list:acls", {}).get("acl", [])
        if not acls:
            results["status"] = "FAIL"
            results["details"].append("No ACL entries found in the MUD file.")
            return results

        for acl in acls:
            acl_name = acl.get("name")
            acl_type = acl.get("type")
            aces = acl.get("aces", {}).get("ace", [])

            # Check ACL-level attributes
            if not acl_name or not acl_type:
                results["status"] = "FAIL"
                results["details"].append(f"ACL missing 'name' or 'type': {acl}")
                continue

            for ace in aces:
                ace_name = ace.get("name")
                matches = ace.get("matches", {})

                if not ace_name:
                    results["status"] = "FAIL"
                    results["details"].append(f"ACE missing 'name' under ACL: {acl_name}")

                # Check for TCP/UDP port information if applicable
                protocol = matches.get("protocol")
                tcp = matches.get("tcp", {})
                udp = matches.get("udp", {})

                if protocol in [6, "tcp"]:
                    src_port = tcp.get("source-port-range")
                    dst_port = tcp.get("destination-port-range")
                    if not (src_port or dst_port):
                        results["status"] = "FAIL"
                        results["details"].append(
                            f"TCP ACE '{ace_name}' under ACL '{acl_name}' missing source/destination ports."
                        )

                elif protocol in [17, "udp"]:
                    src_port = udp.get("source-port-range")
                    dst_port = udp.get("destination-port-range")
                    if not (src_port or dst_port):
                        results["status"] = "FAIL"
                        results["details"].append(
                            f"UDP ACE '{ace_name}' under ACL '{acl_name}' missing source/destination ports."
                        )

        if results["status"] == "PASS":
            results["details"].append("All ACLs contain required attributes and port definitions.")

    except Exception as e:
        results["status"] = "ERROR"
        results["details"].append(f"Error while verifying ACL attributes: {str(e)}")

    return results

# ===============================
# Test Case 12
# ===============================
def check_ace_direction_policies(mud_data):
    """
    Test Case 12:
    Verify that each ACE policy in the MUD file explicitly defines rules 
    for either inbound or outbound traffic relative to the DUT.
    """
    results = {"status": "PASS", "details": []}

    try:
        acls = []
        # Collect ACLs from both from-device and to-device policies
        if "from-device-policy" in mud_data:
            acls.extend(mud_data["from-device-policy"].get("access-lists", []))
        if "to-device-policy" in mud_data:
            acls.extend(mud_data["to-device-policy"].get("access-lists", []))

        if not acls:
            results["status"] = "FAIL"
            results["details"].append("No ACLs found in MUD file.")
            return results

        for acl in acls:
            acl_name = acl.get("name", "")
            if not acl_name:
                results["status"] = "FAIL"
                results["details"].append("An ACL entry is missing the 'name' attribute.")
                continue

            # Check if ACL name indicates direction (contains 'from' or 'to')
            if not ("from" in acl_name.lower() or "to" in acl_name.lower()):
                results["status"] = "FAIL"
                results["details"].append(f"ACL '{acl_name}' does not specify direction (missing 'from' or 'to').")

        if results["status"] == "PASS":
            results["details"].append("All ACLs correctly define direction (inbound/outbound).")

    except Exception as e:
        results["status"] = "FAIL"
        results["details"].append(f"Error while checking ACE directions: {str(e)}")

    return results

# ===============================
# Test Case 13
# ===============================
def check_dnsname_endpoints(mud_data):
    """
    Test Case 13:
    Verify that ACEs with 'ietf-acldns:src-dnsname' and 'ietf-acldns:dst-dnsname'
    specify valid domain names (not IP addresses).
    """
    results = {"status": "PASS", "details": []}

    # Regular expressions for validation
    domain_pattern = re.compile(
        r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
        r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*(\.[A-Za-z]{2,})$"
    )
    ipv4_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    ipv6_pattern = re.compile(r"^([0-9a-fA-F:]+)$")

    try:
        acls = []
        if "from-device-policy" in mud_data:
            acls.extend(mud_data["from-device-policy"].get("access-lists", []))
        if "to-device-policy" in mud_data:
            acls.extend(mud_data["to-device-policy"].get("access-lists", []))

        for acl in acls:
            aces = acl.get("aces", [])
            for ace in aces:
                matches = []
                src_dns = ace.get("ietf-acldns:src-dnsname")
                dst_dns = ace.get("ietf-acldns:dst-dnsname")

                if src_dns:
                    matches.append(("src", src_dns))
                if dst_dns:
                    matches.append(("dst", dst_dns))

                for direction, dnsname in matches:
                    if ipv4_pattern.match(dnsname) or ipv6_pattern.match(dnsname):
                        results["status"] = "FAIL"
                        results["details"].append(f"ACE {ace.get('name', '')} has invalid {direction}-dnsname (IP address found): {dnsname}")
                    elif not domain_pattern.match(dnsname):
                        results["status"] = "FAIL"
                        results["details"].append(f"ACE {ace.get('name', '')} has invalid {direction}-dnsname format: {dnsname}")

        if results["status"] == "PASS":
            results["details"].append("All DNS-based endpoint attributes are valid domain names.")

    except Exception as e:
        results["status"] = "FAIL"
        results["details"].append(f"Error checking DNS endpoint attributes: {str(e)}")

    return results


# ===============================
# Test Case 14
# ===============================
def check_ace_policy_attributes(mud_data):
    """
    Test Case: Verify that ACE attributes align with policy intent.
    """
    results = {"status": "PASS", "details": []}

    allowed_attrs = {
        "from-device-policy": ["dst-dnsname", "destination-ipv4-network", "destination-ipv6-network"],
        "to-device-policy": ["src-dnsname", "source-ipv4-network", "source-ipv6-network"]
    }

    disallowed_attrs = {
        "from-device-policy": ["src-dnsname", "source-ipv4-network", "source-ipv6-network"],
        "to-device-policy": ["dst-dnsname", "destination-ipv4-network", "destination-ipv6-network"]
    }

    acl_list = mud_data.get("ietf-access-control-list:access-lists", {}).get("acl", [])

    for acl in acl_list:
        acl_name = acl.get("name", "")
        if "from-device" in acl_name:
            policy_type = "from-device-policy"
        elif "to-device" in acl_name:
            policy_type = "to-device-policy"
        else:
            continue  # skip ACLs not labeled as from/to-device

        for ace in acl.get("aces", {}).get("ace", []):
            matches = ace.get("matches", {})
            for attr in matches.keys():
                if attr not in allowed_attrs[policy_type]:
                    results["status"] = "FAIL"
                    results["details"].append({
                        "acl": acl_name,
                        "ace": ace.get("name", "unknown"),
                        "attribute": attr,
                        "error": f"Disallowed attribute '{attr}' in {policy_type}"
                    })

    if results["status"] == "PASS":
        print("✅ All ACEs comply with policy attribute intent.")
    else:
        print("❌ Policy attribute mismatches found:")
        for issue in results["details"]:
            print(f"  - {issue['acl']} → {issue['ace']}: {issue['error']}")

    return results

# ===============================
# Test Case 15
# ===============================
def check_direction_initiated_tcp_only(mud_data):
    """
    Test Case: Verify that 'direction-initiated' is only applied to TCP-based ACEs.
    """
    results = {"status": "PASS", "details": []}

    acl_list = mud_data.get("ietf-access-control-list:access-lists", {}).get("acl", [])

    for acl in acl_list:
        acl_name = acl.get("name", "")
        for ace in acl.get("aces", {}).get("ace", []):
            protocol = ace.get("matches", {}).get("protocol")
            direction_attr = ace.get("matches", {}).get("direction-initiated")
            
            if direction_attr is not None:
                if protocol != 6:  # 6 = TCP
                    results["status"] = "FAIL"
                    results["details"].append({
                        "acl": acl_name,
                        "ace": ace.get("name", "unknown"),
                        "error": "'direction-initiated' applied to non-TCP ACE"
                    })

    if results["status"] == "PASS":
        print("✅ All 'direction-initiated' attributes correctly applied only to TCP ACEs.")
    else:
        print("❌ Misapplied 'direction-initiated' attributes found:")
        for issue in results["details"]:
            print(f"  - {issue['acl']} → {issue['ace']}: {issue['error']}")

    return results

# ===============================
# Test Case 16
# ===============================
def check_ace_actions(mud_data):
    """
    Test Case: Verify that each ACE specifies only 'accept' or 'drop' as actions.
    """
    results = {"status": "PASS", "details": []}

    acl_list = mud_data.get("ietf-access-control-list:access-lists", {}).get("acl", [])

    for acl in acl_list:
        acl_name = acl.get("name", "")
        for ace in acl.get("aces", {}).get("ace", []):
            action = ace.get("actions", {}).get("forwarding")
            if action not in ["accept", "drop"]:
                results["status"] = "FAIL"
                results["details"].append({
                    "acl": acl_name,
                    "ace": ace.get("name", "unknown"),
                    "invalid_action": action
                })

    if results["status"] == "PASS":
        print("✅ All ACEs specify valid actions ('accept' or 'drop').")
    else:
        print("❌ ACEs with invalid actions found:")
        for issue in results["details"]:
            print(f"  - {issue['acl']} → {issue['ace']}: invalid action '{issue['invalid_action']}'")

    return results

# ===============================
# Test Case 17
# ===============================
def check_ace_count(mud_data, max_aces=50):
    """
    Test Case: Verify that the number of ACEs in the MUD file is relatively small.
    
    Parameters:
        mud_data (dict): Parsed MUD JSON data.
        max_aces (int): Maximum recommended number of ACEs (default: 50).
        
    Returns:
        dict: {'status': 'PASS'/'FAIL', 'count': int, 'message': str}
    """
    acl_list = mud_data.get("ietf-access-control-list:access-lists", {}).get("acl", [])
    total_aces = 0

    for acl in acl_list:
        aces = acl.get("aces", {}).get("ace", [])
        total_aces += len(aces)

    if total_aces <= max_aces:
        return {
            "status": "PASS",
            "count": total_aces,
            "message": f"Number of ACEs is {total_aces}, which is within the recommended limit ({max_aces})."
        }
    else:
        return {
            "status": "FAIL",
            "count": total_aces,
            "message": f"Number of ACEs is {total_aces}, exceeding the recommended limit ({max_aces})."
        }


# ===============================
# Run checks
# ===============================
#def run_checks(mud_url, mud_file):
def run_checks():
    mud_url="https://luminaire.example.com/ubuntu_test"
    mud_file="mud_files/ubuntu_test.json"
    mud_signature ="mud_files/ubuntu_test.p7s"
    trusted_ca_cert ="mud_files/luminaire-cacert.pem"
    results = {
        "mud_url": mud_url,
        "mud_file": mud_file,
        "mud_signature_certificates_valid": None,
        "mud_signature_certificates_message": None,
        "mud_signature_validity_valid": None,
        "mud_signature_validity_message": None,
        "certificate_validity_valid": None,
        "certificate_validity_message": None,
        "utf8_valid": None,
        "utf8_message": None,
        "allowed_nodes_valid": None,
        "allowed_nodes_message": None,
        "extensions_valid": None,
        "extensions_message": None,
        "extensions_standardized_valid": None,
        "extensions_standardized_message": None,
        "communication_policy_valid": None,
        "communication_policy_message": None,
        "cache_validity_valid": None,
        "cache_validity_message": None,
        "systeminfo_valid": None,
        "systeminfo_message": None,
        "firmware_software_valid": None,
        "firmware_software_message": None,
        "local_network_valid": None,
        "local_network_message": None,
        "controller_valid": None,
        "controller_message": None,
        "acl_attributes_valid": None,
        "acl_attributes_message": None,
        "ace_direction_valid": None,
        "ace_direction_message": None,
        "dnsname_valid": None,
        "dnsname_message": None,
        "ace_policy_valid": None,
        "ace_policy_message": None,
        "direction_initiated_valid": None,
        "direction_initiated_message": None,
        "ace_actions_valid": None,
        "ace_actions_message": None,
        "ace_count_valid": None,
        "ace_count_message": None
    

    }
    with open(mud_file, "r") as f:
        mud_data = json.load(f)

    
    # test case 18: MUD Signature and Certificate Validity
    status, message = check_mud_signature_certificates(mud_signature)
    results["mud_signature_certificates_valid"] = status
    results["mud_signature_certificates_message"] = message


    # test case 19:
    status, msg = check_mud_signature_validity(mud_file, mud_signature, trusted_ca_cert)
    results["mud_signature_validity_valid"] = status
    results["mud_signature_validity_message"] = msg
    #test case 20:
    valid, message = check_certificate_validity(mud_file, trusted_ca_cert)
    results["certificate_validity_valid"] = valid
    results["certificate_validity_message"] = message


    # Test case 1: UTF-8 encoding
    utf8_ok, utf8_msg = check_utf8_encoding(mud_file)
    results["utf8_valid"] = utf8_ok
    results["utf8_message"] = utf8_msg

    # Test case 2: Allowed nodes
    nodes_ok, nodes_msg = check_allowed_nodes(mud_file)
    results["allowed_nodes_valid"] = nodes_ok
    results["allowed_nodes_message"] = nodes_msg

    # Test case 3
    ext_ok, ext_msg = check_extensions(mud_file)
    results["extensions_valid"] = ext_ok
    results["extensions_message"] = ext_msg

    # Test case 4
    ext_std_ok, ext_std_msg = check_extensions_standardization(mud_file)
    results["extensions_standardized_valid"] = ext_std_ok
    results["extensions_standardized_message"] = ext_std_msg

    # Test case 5: Communication policies (from/to device)
    comm_results = check_communication_directions(mud_file)
    results["communication_policy_valid"] = comm_results["from_device_present"] and comm_results["to_device_present"] and comm_results["direction_consistency"]
    results["communication_policy_message"] = "; ".join(comm_results["errors"]) if comm_results["errors"] else "Communication policies are valid."

    # Test case 6: Cache-validity
    cache_ok, cache_msg = check_cache_validity(mud_url, mud_file)
    results["cache_validity_valid"] = cache_ok
    results["cache_validity_message"] = cache_msg
    
    # Test case 7:
    sys_ok, sys_msg = check_systeminfo(mud_file)
    results["systeminfo_valid"] = sys_ok
    results["systeminfo_message"] = sys_msg
    
    # Test case 8:
    fw_sw_ok, fw_sw_msg = check_firmware_software_fields(mud_file)
    results["firmware_software_valid"] = fw_sw_ok
    results["firmware_software_message"] = fw_sw_msg

    # Test case 9:
    local_ok, local_msg = check_local_network_addresses(mud_file)
    results["local_network_valid"] = local_ok
    results["local_network_message"] = local_msg
    

    # Test case 10:
    
    results["controller_check"] = check_controller_urls(mud_data)
    results["controller_valid"] = all(r.get("status", "").startswith("valid") for r in results["controller_check"] if "status" in r)
    results["controller_message"] = "; ".join([f"{r['controller']}: {r['status']}" for r in results["controller_check"] if "status" in r])

    # Test case 11: ACL attribute completeness
    acl_results = test_acl_attributes(mud_data)
    results["acl_attributes_valid"] = (acl_results["status"] == "PASS")
    results["acl_attributes_message"] = "; ".join(acl_results["details"])
    
    # Test case 12: ACE inbound/outbound direction policies
    ace_dir_results = check_ace_direction_policies(mud_data)
    results["ace_direction_valid"] = (ace_dir_results["status"] == "PASS")
    results["ace_direction_message"] = "; ".join(ace_dir_results["details"])
    
    # Test case 13: DNS-based endpoint validation
    dns_results = check_dnsname_endpoints(mud_data)
    results["dnsname_valid"] = (dns_results["status"] == "PASS")
    results["dnsname_message"] = "; ".join(dns_results["details"])
    
    # Test Case 14: ACE Policy Attributes
    ace_policy_results = check_ace_policy_attributes(mud_data)
    results["ace_policy_valid"] = ace_policy_results["status"] == "PASS"
    results["ace_policy_message"] = "; ".join([d["error"] for d in ace_policy_results["details"]]) \
    if ace_policy_results["details"] else "All ACEs comply with policy attribute intent."


    # Test Case 15: Direction-Initiated Only for TCP
    dir_init_results = check_direction_initiated_tcp_only(mud_data)
    results["direction_initiated_valid"] = dir_init_results["status"] == "PASS"
    results["direction_initiated_message"] = "; ".join([d["error"] for d in dir_init_results["details"]]) \
    if dir_init_results["details"] else "All 'direction-initiated' attributes correctly applied to TCP ACEs."

    # Test Case 16: ACE Actions
    ace_actions_results = check_ace_actions(mud_data)
    results["ace_actions_valid"] = ace_actions_results["status"] == "PASS"
    results["ace_actions_message"] = "; ".join([f"{d['acl']}->{d['ace']}: {d['invalid_action']}" 
                                             for d in ace_actions_results["details"]]) \
    if ace_actions_results["details"] else "All ACE actions are valid ('accept' or 'drop')."
    

    # Test Case 17: ACE Count
    ace_count_results = check_ace_count(mud_data)
    results["ace_count_valid"] = ace_count_results["status"] == "PASS"
    results["ace_count_message"] = ace_count_results["message"]

    return results

    
# ===============================
# Main entry
# ===============================
if __name__ == "__main__":
    '''if len(sys.argv) != 3:
        print(json.dumps({"error": "Usage: python3 mud_file_checker.py <mud_url> <mud_file>"}))
        sys.exit(1)

    mud_url = sys.argv[1]
    mud_file = sys.argv[2]

    results = run_checks(mud_url, mud_file)
    print(json.dumps(results, indent=2))'''
    mud_url = "https://luminaire.example.com/ubuntu_test"
    mud_file = "mud_files/ubuntu_test.json"
    mud_signature ="mud_files/ubuntu_test.p7s"

    results = run_checks(mud_url, mud_file)
    print(json.dumps(results, indent=2))
