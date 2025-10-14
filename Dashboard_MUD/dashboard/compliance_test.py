import subprocess
from .models import IoTDevice
import json
from .testcases_verification import run_checks
def run_device_test(device_mac):
    testcase_map = {
        "mud_url_emission": "MUD.1.1.1",
        "url_consistent": "MUD.1.1.2",
    "mud_url_valid": "MUD.1.1.3",
    "mud_file_retrieved": "MUD.1.1.4",
    "signature_present": "MUD.1.1.5",
    "verify_cert": "MUD.1.1.6",
    "cert_integrity": "MUD.1.1.7",
    "cert_validity": "MUD.1.1.8",
    "valid_json": "MUD.1.2.1",
    "utf8_valid": "MUD.1.2.2",
    "allowed_nodes_valid": "MUD.1.2.3",
    "extensions_valid": "MUD.1.2.4",
    "extensions_standardized_valid": "MUD.1.2.5",
    "communication_policy_valid": "MUD.1.3.1",
    "cache_validity_valid": "MUD.1.3.2",
    "systeminfo_valid": "MUD.1.3.3",
    "firmware_software_valid": "MUD.1.3.4",
    "local_network_valid": "MUD.1.4.1",
    "controller_valid": "MUD.1.4.2",
    "acl_attributes_valid": "MUD.1.5.1",
    "ace_direction_valid": "MUD.1.5.2",
    "dnsname_valid": "MUD.1.5.3",
    "ace_policy_valid": "MUD.1.5.4",
    "direction_initiated_valid": "MUD.1.5.5",
    "ace_actions_valid": "MUD.1.5.6",
    "ace_count_valid": "MUD.1.5.7",
}

    pcapfile="/home/iot/Documents/MUD/MUD_Analytics/Dashboard/Dashboard_MUD/dashboard/mud-capture.pcap"
    try:
        device = IoTDevice.objects.get(mac_address=device_mac)
    except IoTDevice.DoesNotExist:
        return {"error": f"Device with MAC {device_mac} not found."}

    passed = 0
    failed = 0
    details = []
    test_passed = None
    message = ""
    # Test 1: MUD URL exists
    if device.mud_url:
        passed += 1
        test_passed = True
        message = "MUD URL is present."
    else:
        failed += 1
        test_passed = False
        message = "MUD URL is missing."
    details.append({
            "test_case_number": testcase_map.get("mud_url_emission", "unknown"),
            "test_case_name": "mud_url_emission",
            "passed": test_passed,
            "message": message
        })
       
    test_passed = None
    message = ""
    # Step 2: Call external python script with pcap file
    try:
        result = subprocess.run(
            ["python3", "/home/iot/Documents/MUD/MUD_Analytics/Dashboard/Dashboard_MUD/dashboard/url_validate.py", pcapfile],
            capture_output=True,
            text=True,
            timeout=30  # adjust as needed
        )
        
        output = result.stdout.strip()
      
        if "Ok" in output:
            passed += 1
            test_passed = True
            message = "MUD URL is valid."

        else:
            failed += 1
            test_passed = False
            message = "MUD URL is not valid."
        details.append({
            "test_case_number": testcase_map.get("mud_url_valid", "unknown"),
            "test_case_name": "mud_url_valid",
            "passed": test_passed,
            "message": message
        })
           
        
    except subprocess.SubprocessError as e:
        print(f"Error running url_validate.py: {e}")
        failed += 1
    
    # Test 3: Call tests.py with mud_url
    test_passed = None
    message = ""
    if device.mud_url:
        try:
            result = subprocess.run(
                ["python3", "/home/iot/Documents/MUD/MUD_Analytics/Dashboard/Dashboard_MUD/dashboard/tests.py", device.mud_url],
                capture_output=True,
                text=True,
                timeout=30
            )
            output = result.stdout.strip()
            print(output)
            # Parse JSON output
            data = json.loads(output)
            # Check if MUD file exists
            if data.get("retrieved") is True:
                passed += 1
                test_passed = True
                message = "MUD file retrieved successfully."
            else:
                failed += 1
                test_passed = False
                message = "Failed to retrieve MUD file."
            details.append({
                "test_case_number": testcase_map.get("mud_file_retrieved", "unknown"),
                "test_case_name": "mud_file_retrieved",
                "passed": test_passed,
                "message": message  
            })

            # ✅ Check if signature is valid
            test_passed = None
            message = ""
            if data.get("signature_valid") is True:
                passed += 1
                test_passed = True
                message = "Signature is valid."
            else:
                failed += 1
                test_passed = False
                message = "Signature is invalid."
            details.append({
                "test_case_number": testcase_map.get("signature_present", "unknown"),
                "test_case_name": "signature_present",
                "passed": test_passed,
                "message": message  
            })

        except subprocess.SubprocessError as e:
            print(f"Error running tests.py: {e}")
            failed += 2  # count both retrieval + signature as failed
        except json.JSONDecodeError:
            print("Invalid JSON returned from tests.py")
            failed += 2

    #if mud_file_path:
    #results = run_checks(device.mud_url, mud_file_path)
    results = run_checks()
    print(results)
    
    for key, value in results.items():
        if key.endswith("_valid"):
            test_passed = None          
            if value is True:
                passed += 1
                test_passed = True
            elif value is False:
                failed += 1
                test_passed = False
                # None = skip 
            details.append({
            "test_case_number": testcase_map.get(key, "unknown"),
            "test_case_name": key,
            "passed": test_passed,
            "message": results.get(key.replace("_valid", "_message"), "")
        })
    #print(passed, failed)

    # Save updated device
    device.testcases_passed = passed
    device.testcases_failed = failed
    device.save()
    #context['device_json'] = json.dumps(device_data, cls=DjangoJSONEncoder)
    return {
        "mac_address": device.mac_address,
        "testcases_passed": device.testcases_passed,
        "testcases_failed": device.testcases_failed,
        "total": device.testcases_passed + device.testcases_failed,
        "details": details
    } 