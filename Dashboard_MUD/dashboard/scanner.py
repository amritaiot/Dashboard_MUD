import requests
from .models import IoTDevice


def fetch_and_save_devices():
    devices_url = "http://10.72.72.1/cgi-bin/active_devices.sh"
    mud_url_api = "http://10.72.72.1/cgi-bin/send_muddevices.sh"
    check_mud_api = "http://127.0.0.1:5000/check_mud"
    try:
        response = requests.get(devices_url, timeout=5)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Error fetching devices: {e}")
        return []

    mud_urls = {}
    try:
        mud_response = requests.get(mud_url_api, timeout=5)
        mud_response.raise_for_status()
        lines = mud_response.text.splitlines()
        current_mac = None
        for line in lines:
            line = line.strip()
            if line.startswith("MAC:"):
                current_mac = line.split(":", 1)[1].strip().lower()
            elif line.startswith("MUD URL:") and current_mac:
                url = line.split(":", 1)[1].strip()
                mud_urls[current_mac] = url
            elif line.startswith("-" * 25):
                current_mac = None  # reset for next entry
    except requests.RequestException as e:
        print(f"Error fetching MUD URLs: {e}")
   
    devices = []
    lines = response.text.splitlines()
    active_macs = set()
    device_data = {}
    for line in lines:
        line = line.strip()
        if line.startswith("IP:"):
            device_data["ip"] = line.split(":", 1)[1].strip()
        elif line.startswith("MAC:"):
            device_data["mac"] = line.split(":", 1)[1].strip().lower()
        elif line.startswith("Host:"):
            device_data["host"] = line.split(":", 1)[1].strip()
        elif line.startswith("State:"):
            device_data["state"] = line.split(":", 1)[1].strip()
        elif line.startswith("-" * 37):
            if device_data:
                mac = device_data.get("mac")
                active_macs.add(mac)
                mud_url = mud_urls.get(mac, "")  # Get corresponding MUD URL if exists
                
                mud_compliant = False
                
                if mud_url:
                    
                    try:
                        check_response = requests.get(f"{check_mud_api}?mud_url={mud_url}", timeout=5)
                      
                        if check_response.status_code == 200:
                            data = check_response.json()  # parse JSON
                            if data.get("exists") is True:
                                mud_compliant = True
                    except requests.RequestException as e:
                        print(f"Error checking MUD for {mac}: {e}")
                
                obj, created = IoTDevice.objects.update_or_create(
                    ip_address=device_data.get("ip"),
                    defaults={
                        "mac_address": mac,
                        "name": device_data.get("host"),
                        "state": device_data.get("state"),
                        "mud_url": mud_url,
                        "mud_compliant": mud_compliant,
                    },
                )
                devices.append(obj)
            device_data = {}

    # Handle last device if file does not end with separator
    if device_data:
        mac = device_data.get("mac")
        mud_url = mud_urls.get(mac, "")
        active_macs.add(mac)
        mud_compliant = False
        if mud_url:
            try:
                check_response = requests.get(f"{check_mud_api}?mud_url={mud_url}", timeout=5)
                if check_response.status_code == 200 and check_response.text.lower() == "true":
                    mud_compliant = True
            except requests.RequestException as e:
                print(f"Error checking MUD for {mac}: {e}")

        obj, created = IoTDevice.objects.update_or_create(
            ip_address=device_data.get("ip"),
            defaults={
                "mac_address": mac,
                "name": device_data.get("host"),
                "state": device_data.get("state"),
                "mud_url": mud_url,
                "mud_compliant": mud_compliant,
            },
        )
        devices.append(obj)
    IoTDevice.objects.exclude(mac_address__in=active_macs).update(state="UNREACHABLE")
    return devices