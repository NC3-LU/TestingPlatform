import json

from django.contrib.auth.decorators import login_required
from subprocess import check_output
from django.shortcuts import render
import requests


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
        ################################
        # HTTP SCAN Mozilla Observatory
        ################################
        target = request.POST['target']
        rescan = True

        if rescan is True:
            do_scan = requests.post(
                'https://http-observatory.security.mozilla.org/api/v1/analyze?host=' + target + '&rescan=true').text
        else:
            do_scan = requests.post('https://http-observatory.security.mozilla.org/api/v1/analyze?host=' + target).text

        json_object = json.loads(do_scan)
        headers = {}
        use = True

        if 'error' in json_object:
            if json_object['error'] == 'invalid-hostname':
                return render(request, 'check_website.html', {'error': 'You entered an invalid hostname!'})
        else:
            scan_history = json.loads(requests.get(
                'https://http-observatory.security.mozilla.org/api/v1/getHostHistory?host=' + target).text)
            scan_id = json_object['scan_id']
            scan_summary = json_object

            while json_object['state'] == "PENDING" or json_object['state'] == "STARTING" or json_object[
                'state'] == "RUNNING":
                get_scan = requests.get(
                    'https://http-observatory.security.mozilla.org/api/v1/analyze?host=' + target).text
                check_object = json.loads(get_scan)
                if check_object["state"] == 'FINISHED':
                    use = False
                    headers = {k.replace('-', '_'): v for k, v in check_object['response_headers'].items()}
                    scan_id = check_object['scan_id']
                    scan_summary = check_object
                    break

            result_obj = json.loads(requests.get(
                'https://http-observatory.security.mozilla.org/api/v1/getScanResults?scan=' + str(scan_id)).text)

            response = {k.replace('-', '_'): v for k, v in result_obj.items()}
            if use:
                headers = {k.replace('-', '_'): v for k, v in json_object['response_headers'].items()}

            ################################
            # TLS SCAN Mozilla Observatory
            ################################
            tls_target = target.replace('www.', '')

            if rescan is True:
                do_tls_scan = json.loads(requests.post(
                    'https://tls-observatory.services.mozilla.com/api/v1/scan?target=' + tls_target + '&rescan=true').text)
            else:
                do_tls_scan = json.loads(requests.post(
                    'https://http-observatory.security.mozilla.org/api/v1/analyze?host=' + tls_target).text)
            tls_scan_id = do_tls_scan['scan_id']
            # TODO Finish TLS Observatory Data fetching

            return render(request, 'check_website.html',
                          {'result': response, 'domain_name': target, 'scan_summary': scan_summary, 'headers': headers,
                           'scan_history': scan_history, 'tls_results': do_tls_scan})
    else:
        return render(request, 'check_website.html')
