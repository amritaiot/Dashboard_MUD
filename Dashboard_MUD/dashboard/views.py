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
    return render(request, 'home.html', {'devices': devices})

def testcase_view(request):
    return render(request, "testcases.html")