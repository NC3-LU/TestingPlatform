import platform  # For getting the operating system name
import subprocess  # For executing a shell command
from django.contrib.auth.decorators import login_required
from subprocess import check_output
from django.shortcuts import render


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
    # Render the HTML template signup.html
    return render(request, 'test_landing.html')