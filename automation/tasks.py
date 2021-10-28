from django.contrib import messages

from testing.helpers import get_observatory_report
import socket
from ipwhois import IPWhois, IPDefinedError


def ping(host):
    # response = subprocess.Popen(['ping', host, '-c', '2', '-W', '4'])
    # response.wait()
    # return response.poll()
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return {'code': 1, 'result': f'The hostname {host} could not be resolved'}
    try:
        whois = IPWhois(ip)
    except IPDefinedError:
        return {'code': 2, 'result': f'You are not authorized to test {host}'}
    except ValueError:
        return {'code': 3, 'result': f"The ip address {ip} doesn't seem to be an IPv4 / IPv6 address"}
    ping_result = whois.lookup_rdap(depth=1)
    return {'code': 0, 'result': ping_result}


def http(host):
    return get_observatory_report(host)
