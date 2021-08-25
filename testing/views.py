from django.shortcuts import render
#from .models import PingTest

import platform    # For getting the operating system name
import subprocess  # For executing a shell command
from subprocess import check_output
# Create your views here.


def ping_test(request):
    if request.method == 'POST':
        target = request.POST['ping-target']
        """
        Returns True if host (str) responds to a ping request.
        Remember that a host may not respond to a ping (ICMP) request even if the host name is valid.
        """
        command = ['ping', '-c', '2', target, '-q']
        #ping_result = subprocess.call(command) == 0
        ping_result = check_output(command)
        ping_result = ping_result.decode("utf-8")
#        if ping_result == True:
#            result = "Target successfully pinged"
#        else:
#            result =  "Unable to ping target"
        return render(request, 'ping_test.html', {'result':ping_result})
    else:
        return render(request, 'ping_test.html')