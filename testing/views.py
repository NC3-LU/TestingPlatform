
from django.contrib.auth.decorators import login_required
from django.shortcuts import render

import json
from subprocess import check_output
import requests
from .helpers import get_observatory_report


# Create your views here.


@login_required
def ping_test(request):
    if request.method == 'POST':
        target = request.POST['ping-target']
        """
        Returns True if host (str) responds to a ping request.
        Remember that a host may not respond to a ping (ICMP) request even if the host name is valid.
        """
        command = ['ping', '-c', '2', target, '-q']
        # ping_result = subprocess.call(command) == 0
        ping_result = check_output(command)
        ping_result = ping_result.decode("utf-8")
        #        if ping_result == True:
        #            result = "Target successfully pinged"
        #        else:
        #            result =  "Unable to ping target"
        return render(request, 'ping_test.html', {'result': ping_result})
    else:
        return render(request, 'ping_test.html')


@login_required
def test_landing(request):
    return render(request, 'test_landing.html')


@login_required
def c3_protocols(request):
    return render(request, 'c3_protocols.html')


@login_required
def check_website(request):
    if request.method == 'POST':
        context = get_observatory_report(request.POST['target'])
        return render(request, 'check_website.html', context=context)
    else:
        return render(request, 'check_website.html')
