import subprocess
import os
import re
from .models import IoTDevice
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import redirect
from dashboard.models import IoTDevice
from django.conf import settings
from django.contrib import messages
from collections import defaultdict
from django.http import JsonResponse
import json
from django.shortcuts import render
from .scanner import fetch_and_save_devices
from .compliance_test import run_device_test
from django.http import JsonResponse
from django.core.serializers.json import DjangoJSONEncoder
def active_devices_view(request):
    devices = fetch_and_save_devices()
    devices = IoTDevice.objects.all().order_by("ip")
    return render(request, "active_devices.html", {"devices": devices})

def home(request):
    if request.method == "POST" and "rescan" in request.POST:
        # Fetch live data and save/update in DB
        fetch_and_save_devices()
    
    # Always read the current devices from DB
    devices = IoTDevice.objects.all()
    testcase_devices = IoTDevice.objects.filter(state="REACHABLE", mud_compliant=True)
    return render(request, 'home.html', {
        'devices': devices,
        "testcase_devices": testcase_devices})

def testcase_view(request):
    return render(request, "testcases.html")

'''def dashboard(request):
    devices = IoTDevice.objects.all()
    testcase_devices = IoTDevice.objects.filter(state="ON", mud_compliant=True)
    return render(request, "dashboard.html", {
        "devices": devices,
        "testcase_devices": testcase_devices
    })'''

def run_test_view(request):
    mac = request.GET.get("mac")
    #pcapfile = request.GET.get("pcapfile", "capture.pcap")  # default pcap if not sent

    if not mac:
        return JsonResponse({"error": "MAC address missing"}, status=400)

    #result = run_device_test(mac, pcapfile)
    result = run_device_test(mac)
    return JsonResponse(result)

def device_testcases(request, mac):
    device = IoTDevice.objects.get(mac_address=mac)
    testcases = device.testcase_set.all()
    data = [{
        "test_case_number": t.number,
        "test_case_name": t.name,
        "passed": t.passed,
        "message": t.message
    } for t in testcases]
    return JsonResponse(data, safe=False)
