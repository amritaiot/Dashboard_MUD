import subprocess
from .models import IoTDevice
import json
from .testcases_verification import run_checks
def run_device_test(device_mac):
    pcapfile="/home/iot/Documents/MUD/MUD_Analytics/Dashboard/Dashboard_MUD/dashboard/mud-capture.pcap"
    try:
        device = IoTDevice.objects.get(mac_address=device_mac)
    except IoTDevice.DoesNotExist:
        return {"error": f"Device with MAC {device_mac} not found."}

    passed = 0
    failed = 0

    # Test 1: MUD URL exists
    if device.mud_url:
        passed += 1
        
    else:
        failed += 1
       

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

        else:
            failed += 1
           
        
    except subprocess.SubprocessError as e:
        print(f"Error running url_validate.py: {e}")
        failed += 1
    
    # Test 3: Call tests.py with mud_url
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
            else:
                failed += 1

            # ✅ Check if signature is valid
            if data.get("signature_valid") is True:
                passed += 1
            else:
                failed += 1

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
            if value is True:
                passed += 1
            elif value is False:
                failed += 1
                # None = skip 
    print(passed, failed)

    # Save updated device
    device.testcases_passed = passed
    device.testcases_failed = failed
    device.save()

    return {
        "mac_address": device.mac_address,
        "testcases_passed": device.testcases_passed,
        "testcases_failed": device.testcases_failed,
        "total": device.testcases_passed + device.testcases_failed
    }