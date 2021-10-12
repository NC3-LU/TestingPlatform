import os
from testing.helpers import get_observatory_report


def ping(host):
    response = os.system(f'ping -c 2 {host}')
    return response


def http(host):
    return get_observatory_report(host)
