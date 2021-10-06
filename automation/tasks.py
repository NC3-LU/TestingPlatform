import os


def ping(host):
    response = os.system(f'ping -c 2 {host}')
    return response
