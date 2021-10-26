import os
import subprocess
from testing.helpers import get_observatory_report


def ping(host):
    response = subprocess.Popen(['ping', host, '-c', '2', '-W', '4'])
    response.wait()
    return response.poll()


def http(host):
    return get_observatory_report(host)
