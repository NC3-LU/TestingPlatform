import json
import logging
import os
import re
import socket
import subprocess
import time
from io import BytesIO
from typing import Any, Dict, List, Union

import dns.message
import dns.rdatatype
import dns.resolver
import nmap3
import pypandora
import requests

from testing.models import TlsScanHistory

logger = logging.getLogger(__name__)


def full_domain_validator(hostname):
    """
    Fully validates a domain name as compilant with the standard rules:
        - Composed of series of labels concatenated with dots, as are all domain names.
        - Each label must be between 1 and 63 characters long.
        - The entire hostname (including the delimiting dots) has a maximum of 255 characters.
        - Only characters 'a' through 'z' (in a case-insensitive manner), the digits '0' through '9'.
        - Labels can't start or end with a hyphen.
    """
    HOSTNAME_LABEL_PATTERN = re.compile(r"(?!-)[A-Z\d-]+(?<!-)$", re.IGNORECASE)
    if not hostname:
        return
    if len(hostname) > 255:
        raise Exception(
            "The domain name cannot be composed of more than 255 characters."
        )
    if hostname[-1:] == ".":
        hostname = hostname[:-1]  # strip exactly one dot from the right, if present
    for label in hostname.split("."):
        if len(label) > 63:
            raise Exception(
                "The label '%(label)s' is too long (maximum is 63 characters)."
                % {"label": label}
            )
        if not HOSTNAME_LABEL_PATTERN.match(label):
            raise Exception(f"Unallowed characters in label '{label}'.")
    return hostname


def get_http_report(target, rescan):
    ################################
    # HTTP SCAN Mozilla Observatory
    ################################
    response = {}
    scan_summary = ""
    scan_history = ""

    logger.info(f"http scan: scanning {target}, with rescan set to {rescan}")

    http_url = (
        "https://http-observatory.security.mozilla.org/api/v1/analyze?host=" + target
    )
    if rescan:
        http_url += "&rescan=true"

    do_scan = requests.post(http_url).text

    json_object = json.loads(do_scan)
    headers = {}
    use = True

    if "error" in json_object:
        if json_object["error"] == "invalid-hostname":
            return {"error": "You entered an invalid hostname!"}
    else:
        scan_history = json.loads(
            requests.get(
                "https://http-observatory.security.mozilla.org/api/v1/getHostHistory?host="
                + target
            ).text
        )
        scan_id = json_object["scan_id"]
        scan_summary = json_object
        state = ""
        counter = 0

        while json_object["state"] not in ("ABORTED", "FAILED") and counter < 5:
            get_scan = requests.get(
                "https://http-observatory.security.mozilla.org/api/v1/analyze?host="
                + target
            ).text
            check_object = json.loads(get_scan)
            state = check_object.get("state", "NO_STATE")
            counter += 1
            if state == "FINISHED":
                use = False
                headers = {
                    k.replace("-", "_"): v
                    for k, v in check_object["response_headers"].items()
                }
                scan_id = check_object["scan_id"]
                scan_summary = check_object
                logger.info(f"http scan: finished scan in {counter} request(s)")
                result_obj = json.loads(
                    requests.get(
                        "https://http-observatory.security.mozilla.org/api/v1/getScanResults?scan="
                        + str(scan_id)
                    ).text
                )
                response = {k.replace("-", "_"): v for k, v in result_obj.items()}
                if use:
                    headers = {
                        k.replace("-", "_"): v
                        for k, v in json_object["response_headers"].items()
                    }
                break
            else:
                if state in (
                    "ABORTED",
                    "FAILED",
                    "PENDING",
                    "STARTING",
                    "RUNNING",
                    "NO_STATE",
                ):
                    logger.info(
                        f"http scan: got {state} after {counter} request(s) for {target}, retrying in 3s"
                    )
                    time.sleep(3)
                else:
                    logger.info(f"http scan: got unknown state {state} for {target}")
                    print(f"http scan: got unknown state {state} for {target}")

        if counter == 5 and state != "FINISHED":
            logger.warning("http scan: not finished after 5 times, skipping")

        return {
            "result": response,
            "domain_name": target,
            "scan_summary": scan_summary,
            "headers": headers,
            "scan_history": scan_history,
        }


def get_tls_report(target, rescan):
    ################################
    # TLS SCAN Mozilla Observatory
    ################################
    tls_target = target.replace("www.", "")
    tls_scan_id = ""
    url = (
        "https://tls-observatory.services.mozilla.com/api/v1/scan?target=" + tls_target
    )
    if rescan:
        url += "&rescan=true"
    try:
        do_tls_scan = json.loads(requests.post(url).text)
        tls_scan_id = do_tls_scan["scan_id"]
        TlsScanHistory.objects.update_or_create(
            domain=tls_target, defaults={"scan_id": tls_scan_id}
        )
    except ValueError:
        tls_scan_history = TlsScanHistory.objects.get(domain=tls_target)
        tls_scan_id = tls_scan_history.scan_id

    fetch_tls = json.loads(
        requests.get(
            "https://tls-observatory.services.mozilla.com/api/v1/results?id="
            + str(tls_scan_id)
        ).text
    )

    completion_perc = fetch_tls["completion_perc"]
    counter = 0
    while completion_perc != 100 and counter < 5:
        fetch_tls = json.loads(
            requests.get(
                "https://tls-observatory.services.mozilla.com/api/v1/results?id="
                + str(tls_scan_id)
            ).text
        )
        completion_perc = fetch_tls["completion_perc"]
        counter += 1
        if completion_perc == 100:
            logger.info(f"tls scan: finished scan in {counter} request(s).")
            break
        else:
            logger.info(
                f"tls scan: got {completion_perc}% done for {target} after {counter} request(s), sleeping 3s"
            )
            time.sleep(3)

    if completion_perc < 100 and counter == 5:
        logger.warning("tls scan: scan not finished after 5 tries, skipping")

    return fetch_tls


def email_check(target: str, rescan: bool) -> Dict[str, Any]:
    """Parses and validates MX, SPF, and DMARC records,
    Checks for DNSSEC deployment, Checks for STARTTLS and TLS support."""

    env = os.environ.copy()
    cmd = [
        # sys.exec_prefix + "/bin/python",
        "checkdmarc",
        full_domain_validator(target),
        "-f",
        "JSON",
    ]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    (stdout, stderr) = p.communicate()
    try:
        result = json.loads(stdout)
        # result = checkdmarc.check_domains([target])
        # json_result = checkdmarc.results_to_json(result)
    except Exception:
        result = {}
    return {
        "result": result,
        "domain_name": target,
    }


def file_check(file_in_memory: BytesIO, file_to_check_name: str) -> Dict[str, Any]:
    """Checks a file by submitting it to a Pandora instance."""
    pandora_root_url = "https://pandora.circl.lu/"
    pandora_cli = pypandora.PyPandora(root_url=pandora_root_url)
    analysis_result: Dict[str, Any] = {}

    # Submit the file to Pandora for analysis.
    # scan_start_time = time.time()
    result = pandora_cli.submit(file_in_memory, file_to_check_name, 100)
    if not result["success"]:
        # unsuccessfull submission of the file
        return {
            "result": analysis_result,
        }

    time.sleep(0.1)
    # Get the status of a task.
    analysis_result = pandora_cli.task_status(result["taskId"])
    time.sleep(0.1)
    loop = 0
    while loop < (50 * 10):
        analysis_result = pandora_cli.task_status(analysis_result["taskId"])
        # Handle responde from Pandora
        status = analysis_result["status"]
        if status != "WAITING":
            break

        # wait a little
        pass
        time.sleep(0.1)

        loop += 1
    # scan_end_time = time.time()

    analysis_result.update({"link": result["link"]})

    return {
        "result": analysis_result,
    }


def ipv6_check(
    domain: str, port=None
) -> Dict[str, Union[Dict[Any, Any], List[Union[str, int]], List[Any]]]:

    results = {}

    # Check Name Servers connectivity:
    default_resolver = dns.resolver.Resolver().nameservers[0]
    q = dns.message.make_query(domain, dns.rdatatype.NS)
    ns_response = dns.query.udp(q, default_resolver)
    ns_names = [t.target.to_text() for ans in ns_response.answer for t in ans]
    results["nameservers"] = {}

    for ns_name in ns_names:
        results["nameservers"][ns_name] = {}

        # Test IPv4:
        q = dns.message.make_query(ns_name, dns.rdatatype.A)
        response = dns.query.udp(q, default_resolver)
        if response.answer:
            nameserver_ips = [
                item.address
                for answer in response.answer
                for item in answer.items
                if answer.rdtype == dns.rdatatype.A
            ]
            for nameserver_ip in nameserver_ips:
                q = dns.message.make_query("example.com", dns.rdatatype.A)
                try:
                    udp_response = dns.query.udp(q, nameserver_ip)  # noqa: F841
                    supports_udp_v4 = True
                except dns.exception.Timeout:
                    supports_udp_v4 = False
                try:
                    tcp_response = dns.query.tcp(q, nameserver_ip)  # noqa: F841
                    supports_tcp_v4 = True
                except dns.exception.Timeout:
                    supports_tcp_v4 = False

                if supports_tcp_v4 or supports_udp_v4:
                    reachable = True
                else:
                    reachable = False

                results["nameservers"][ns_name]["ipv4"] = {
                    "address": nameserver_ip,
                    "reachable": reachable,
                }
        else:
            results["nameservers"][ns_name]["ipv4"] = {"address": None}

        # Test IPv6:
        q = dns.message.make_query(ns_name, dns.rdatatype.AAAA)
        response = dns.query.udp(q, default_resolver)
        if response.answer:
            nameserver_ips = [
                item.address
                for answer in response.answer
                for item in answer.items
                if answer.rdtype == dns.rdatatype.AAAA
            ]
            for nameserver_ip in nameserver_ips:
                q = dns.message.make_query("example.com", dns.rdatatype.AAAA)
                connect_udp = True
                connect_tcp = True
                try:
                    udp_response = dns.query.udp(q, nameserver_ip)  # noqa: F841
                except dns.exception.Timeout:
                    connect_udp = False
                except OSError:
                    connect_udp = False
                try:
                    tcp_response = dns.query.tcp(q, nameserver_ip)  # noqa: F841
                except dns.exception.Timeout:
                    connect_tcp = False
                except OSError:
                    connect_tcp = False

                if connect_udp and connect_tcp:
                    reachable = True
                else:
                    reachable = False

                results["nameservers"][ns_name]["ipv6"] = {
                    "address": nameserver_ip,
                    "reachable": reachable,
                }
        else:
            results["nameservers"][ns_name]["ipv6"] = {"address": None}

    # Grading results
    counter = 0
    for key in results["nameservers"]:
        if results["nameservers"][key]["ipv6"]["address"]:
            counter += 1
    if counter >= 2:
        nameservers_comments = {
            "grade": "full",
            "comment": "Your domain has at least 2 name servers with ipv6 records.",
        }
    elif counter == 1:
        nameservers_comments = {
            "grade": "half",
            "comment": "Your domain has 1 name server with an ipv6 record.",
        }
    else:
        nameservers_comments = {
            "grade": "null",
            "comment": "Your domain has no name server with an ipv6 record.",
        }
    counter = 0
    for key in results["nameservers"]:
        if results["nameservers"][key]["ipv6"]["reachable"]:
            counter += 1
    if counter == 0:
        nameservers_reachability_comments = {
            "grade": "null",
            "comment": "Your domain name servers are not reachable over ipv6.",
        }
    else:
        nameservers_reachability_comments = {
            "grade": "full",
            "comment": "At least one of your domain name servers is reachable over ipv6.",
        }

    # Check website connectivity (available ips and reachability)
    try:
        resolved_v4 = socket.getaddrinfo(domain, port, socket.AF_INET)
        records_v4 = [hit[4][0] for hit in resolved_v4]
        records_v4 = list(set(records_v4))
    except socket.gaierror:
        records_v4 = [""]
    try:
        resolved_v6 = socket.getaddrinfo(domain, port, socket.AF_INET6)
        records_v6 = [hit[4][0] for hit in resolved_v6]
        records_v6 = list(set(records_v6))
    except socket.gaierror:
        records_v6 = [""]

    records = [(domain, records_v4[i], records_v6[i]) for i in range(len(records_v4))]

    response = False
    records_v4_comments = None
    if records_v4:
        for ip4 in records_v4:
            command = ["ping", "-c", "1", ip4]
            if subprocess.call(command) == 0:
                response = True
        if response:
            records_v4_comments = {
                "grade": "full",
                "comment": "Your web server is reachable over ipv4.",
            }
        else:
            records_v4_comments = {
                "grade": "null",
                "comment": "Your web server is not reachable over ipv4.",
            }

    response = False
    records_v6_comments = None
    if records_v6:
        for ip6 in records_v6:
            command = ["ping", "-c", "1", ip6]
            if subprocess.call(command) == 0:
                response = True
        if response:
            records_v6_comments = {
                "grade": "full",
                "comment": "Your web server is reachable over ipv6.",
            }
        else:
            records_v6_comments = {
                "grade": "null",
                "comment": "Your web server is not reachable over ipv6.",
            }

    return {
        "nameservers": results["nameservers"],
        "nameservers_comments": nameservers_comments,
        "nameservers_reachability_comments": nameservers_reachability_comments,
        "records": records,
        "records_v4_comments": records_v4_comments,
        "records_v6_comments": records_v6_comments,
    }


def web_server_check(domain: str):
    nmap = nmap3.Nmap()
    service_scans = nmap.nmap_version_detection(
        domain,
        args="--script vulners --script-args mincvss+5.0"
    )
    # Could be used later for better reporting
    # runtime = service_scans.pop("runtime")
    # stats = service_scans.pop("stats")
    # task_results = service_scans.pop("task_results")
    services = []
    vulnerabilities = []
    ip, service_scans = list(service_scans.items())[0]
    for port in service_scans["ports"]:
        if port["state"] != "closed":
            service = port["service"]
            vulners = port["scripts"]
            list_of_vulns = []
            if vulners:
                vulners = vulners[0]["data"]
                for _vuln, vuln_data in vulners.items():
                    try:
                        list_of_vulns += vuln_data["children"]
                    except TypeError:
                        list_of_vulns = []
            services.append(service)
            try:
                vulnerabilities.append(
                    {
                        "service": f'{service["product"]} - {service["name"]}',
                        "vuln_list": list_of_vulns,
                    }
                )
            except KeyError:
                pass
    return {"services": services, "vulnerabilities": vulnerabilities}


def tls_version_check(domain: str):
    nmap = nmap3.Nmap()
    tls_scans = nmap.nmap_version_detection(
        domain,
        args="--script ssl-enum-ciphers"
    )
    ip, tls_scans = list(tls_scans.items())[0]
    tls_scans = list(filter(lambda element: element["state"] == "open",
                            tls_scans["ports"]))
    results = None
    for port in tls_scans:
        if port["service"]["name"] == "ssl":
            for script in port["scripts"]:
                if script["name"] == "ssl-enum-ciphers":
                    results = script["data"]
    least_strength = results.pop("least strength")
    for k in results.keys():
        results[k] = results[k]["ciphers"]["children"]
    results.update({"least_strength": least_strength})
    return results
