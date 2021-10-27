import os
import subprocess
from testing.helpers import get_observatory_report
import socket
from ipwhois import IPWhois


def ping(host):
    # response = subprocess.Popen(['ping', host, '-c', '2', '-W', '4'])
    # response.wait()
    # return response.poll()
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return {'code': 1, 'result': "Can't fetch IP from host"}
    whois = IPWhois(ip)
    ping_result = whois.lookup_rdap(depth=1)
    return {'code': 0, 'result': ping_result}


def http(host):
    return get_observatory_report(host)
