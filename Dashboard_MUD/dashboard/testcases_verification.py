import sys
import json
from datetime import datetime
from email.utils import parsedate_to_datetime
import ipaddress
import re
from urllib.parse import urlparse
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
# Test Case 7: 
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
# Test Case 8: 
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
# Test Case 9: 
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
# Test Case 9: 
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
# Run checks
# ===============================
#def run_checks(mud_url, mud_file):
def run_checks():
    mud_url="https://luminaire.example.com/ubuntu_test"
    mud_file="mud_files/ubuntu_test.json"
    results = {
        "mud_url": mud_url,
        "mud_file": mud_file,
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
    }
    with open(mud_file, "r") as f:
        mud_data = json.load(f)

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
    return results

    # Test case 10:
    results = {}
    results["controller_check"] = check_controller_urls(mud_data)
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

    results = run_checks(mud_url, mud_file)
    print(json.dumps(results, indent=2))
