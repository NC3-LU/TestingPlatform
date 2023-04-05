import socket
import subprocess

from ipwhois import IPDefinedError, IPWhois

from testing.helpers import get_http_report, get_tls_report


def whois_lookup(host):
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return {"code": 1, "result": f"The hostname {host} could not be resolved"}
    try:
        whois = IPWhois(ip)
    except IPDefinedError:
        return {"code": 2, "result": f"You are not authorized to test {host}"}
    except ValueError:
        return {
            "code": 3,
            "result": f"The ip address {ip} doesn't seem to be an IPv4 / IPv6 address",
        }
    ping_result = whois.lookup_rdap(depth=1)
    return {"code": 0, "result": ping_result}


def ping(host):
    response = subprocess.Popen(["ping", host, "-c", "2", "-W", "4"])
    response.wait()
    return response.poll()


def http(host):
    report = get_http_report(host, True)
    report["tls_results"] = get_tls_report(host, True)
    return report
