import sys
import json

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
# Run checks
# ===============================
def run_checks(mud_url, mud_file):
    results = {
        "mud_url": mud_url,
        "mud_file": mud_file,
        "utf8_valid": None,
        "utf8_message": None,
        "allowed_nodes_valid": None,
        "allowed_nodes_message": None,
        "extensions_valid": None,
        "extensions_message": None,
        "extensions_standardized": None,
        "extensions_standardized_message": None,
        "communication_policy_valid": None,
        "communication_policy_message": None
    }

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
    results["extensions_standardized"] = ext_std_ok
    results["extensions_standardized_message"] = ext_std_msg

    # Test case 5: Communication policies (from/to device)
    comm_ok, comm_msg = check_communication_directions(mud_file)
    results["communication_policy_valid"] = comm_ok
    results["communication_policy_message"] = comm_msg


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
