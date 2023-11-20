import json
import logging
import os
import re
import socket
import subprocess
import time
from base64 import b64decode
from io import BytesIO
from typing import Any, Dict, List, Union

import dns.message
import dns.rdatatype
import dns.resolver
import nmap3
import pypandora
import requests
from Crypto.PublicKey import RSA
from django.template.loader import render_to_string
from weasyprint import CSS, HTML

from testing.models import TlsScanHistory
from testing.validators import domain_name, full_domain_validator

from .cipher_scoring import load_cipher_info

logger = logging.getLogger(__name__)


def get_http_report(target, rescan):
    ################################
    # HTTP SCAN Mozilla Observatory
    ################################
    try:
        domain_name(target)
    except Exception:
        return {"error": "You entered an invalid hostname!"}
    response = {}

    logger.info(f"http scan: scanning {target}, with rescan set to {rescan}")

    http_url = (
        "https://http-observatory.security.mozilla.org/api/v1/analyze?host=" + target
    )
    if rescan:
        http_url += "&rescan=true"

    logger.info(f"http scan: requesting scan at {http_url}")
    data = requests.post(http_url)
    json_object = data.json()

    headers = {}

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

        if json_object["state"] == "ABORTED":
            result_obj = json.loads(
                requests.get(
                    "https://http-observatory.security.mozilla.org/api/v1/getScanResults?scan="
                    + str(scan_history[-1]["scan_id"])
                ).text
            )
            response = {k.replace("-", "_"): v for k, v in result_obj.items()}
            return {
                "result": response,
                "domain_name": target,
                "scan_summary": scan_summary,
                "headers": headers,
                "scan_history": scan_history,
            }

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

        logger.info("http scan: Done!")
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


def check_soa_record(target: str) -> Union[bool, Dict]:
    """Checks the presence of a SOA record for the Email Systems Testing."""
    try:
        domain_name(target)
    except Exception:
        return {"status": False, "statusmessage": "The given domain is invalid!"}
    result = False
    try:
        answers = dns.resolver.query(target, "SOA")
        result = 0 != len(answers)
    except Exception:
        result = False
    return result


def email_check(target: str) -> Dict[str, Any]:
    """Parses and validates MX, SPF, and DMARC records,
    Checks for DNSSEC deployment, Checks for STARTTLS and TLS support.
    Checks for the validity of the DKIM public key."""
    try:
        domain_name(target)
    except Exception:
        return {"status": False, "statusmessage": "The given domain is invalid!"}
    result = {}
    env = os.environ.copy()
    cmd = [
        # sys.exec_prefix + "/bin/python",
        "checkdmarc",
        full_domain_validator(target),
        "-f",
        "JSON",
    ]
    (stdout, stderr) = (
        subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    ).communicate()
    try:
        result = json.loads(stdout)
    except Exception:
        result = {}

    # result["dkim"] = check_dkim_public_key(target, [])
    return result


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
    logger.info(f"ipv6 scan: scanning domain {domain}")
    results = {}

    # Check Name Servers connectivity:
    default_resolver = dns.resolver.Resolver().nameservers[0]
    logger.info(f"ipv6 scan: default resolver is {default_resolver}")
    q = dns.message.make_query(domain, dns.rdatatype.NS)
    ns_response = dns.query.udp(q, default_resolver)
    ns_names = [
        t.target.to_text()
        for ans in ns_response.answer
        for t in ans
        if hasattr(t, "target")
    ]
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
                logger.info(f"ipv6 scan: found NS at ip {nameserver_ip}")
                q = dns.message.make_query("https://ciphersuite.info", dns.rdatatype.A)
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
                logger.info(f"ipv6 scan: found NS at ip {nameserver_ip}")
                q = dns.message.make_query(
                    "https://ciphersuite.info", dns.rdatatype.AAAA
                )
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

    logger.info("ipv6 scan: grading results")
    for key in results["nameservers"]:
        if results["nameservers"][key]["ipv6"]["address"]:
            counter += 1
    if counter >= 2:
        nameservers_comments = {
            "grade": "full",
            "comment": "Your domain has at least 2 name servers with IPv6 records.",
        }
    elif counter == 1:
        nameservers_comments = {
            "grade": "half",
            "comment": "Your domain has 1 name server with an IPv6 record.",
        }
    else:
        nameservers_comments = {
            "grade": "null",
            "comment": "Your domain has no name server with an IPv6 record.",
        }
    counter = 0
    for key in results["nameservers"]:
        if results["nameservers"][key]["ipv6"].get("reachable", False):
            counter += 1
    if counter == 0:
        nameservers_reachability_comments = {
            "grade": "null",
            "comment": "Your domain name servers are not reachable over IPv6.",
        }
    else:
        nameservers_reachability_comments = {
            "grade": "full",
            "comment": "At least one of your domain name servers is reachable over IPv6.",
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
                "comment": "Your server is reachable over IPv4.",
            }
        else:
            records_v4_comments = {
                "grade": "null",
                "comment": "Your server is not reachable over IPv4.",
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
                "comment": "Your server is reachable over IPv6.",
            }
        else:
            records_v6_comments = {
                "grade": "null",
                "comment": "Your server is not reachable over IPv6.",
            }

    logger.info("ipv6 scan: Done!")
    return {
        "nameservers": results["nameservers"],
        "nameservers_comments": nameservers_comments,
        "nameservers_reachability_comments": nameservers_reachability_comments,
        "records": records,
        "records_v4_comments": records_v4_comments,
        "records_v6_comments": records_v6_comments,
    }


def web_server_check(domain: str):
    try:
        domain_name(domain)
    except Exception:
        return {"status": False, "statusmessage": "The given domain is invalid!"}
    nmap = nmap3.Nmap()
    logger.info(f"server scan: testing {domain}")
    service_scans = nmap.nmap_version_detection(
        domain, args="--script vulners --script-args mincvss+5.0"
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
                        list_of_vulns += vuln_data.get("children")
                    except TypeError:
                        continue
                    except AttributeError:
                        continue
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
    logger.info("server scan: Done!")
    logger.info(vulnerabilities)
    return {"services": services, "vulnerabilities": vulnerabilities}


def web_server_check_no_raw_socket(hostname):
    try:
        domain_name(hostname)
    except Exception:
        return {"status": False, "statusmessage": "The given domain is invalid!"}
    api_endpoint = "https://vulners.com/api/v3/burp/software/"
    header = {
        "User-Agent": "Vulners NMAP Plugin 1.7",
        "Accept-Encoding": "gzip, deflate",
    }
    version_re = ":([d.-_]+)([^:]*)$"
    nmap = nmap3.Nmap()
    service_scans = nmap.nmap_version_detection(hostname)
    services = []
    vulnerabilities = []
    ip, service_scans = list(service_scans.items())[0]
    for port in service_scans["ports"]:
        if port["state"] != "closed":
            services.append(port["service"])
            cpe_list = port["cpe"]
            vuln_list = []
            for item in cpe_list:
                cpe = item["cpe"]
                version_match = re.search(version_re, cpe)
                if version_match:
                    version, patch = version_match.groups()
                    print(f"Querying vulns for {cpe}, version {version}, of type cpe")
                    query_url = (
                        api_endpoint + f"?software={cpe}&version={version}&type=cpe"
                    )
                    response = requests.get(query_url, headers=header)
                    if response:
                        data = response.json()["data"]["search"]
                        for search_result in data:
                            info = {
                                "id": search_result["id"],
                                "cvss": search_result["_source"]["cvss"]["score"],
                                "type": search_result["_source"]["type"],
                            }
                            if info["type"] == "cve":
                                info[
                                    "link"
                                ] = f"https://cvepremium.circl.lu/cve/{info['id']}"
                            else:
                                info[
                                    "link"
                                ] = f"https://vulners.com/{info['type']}/{info['id']}"
                            vuln_list.append(info)
            try:
                service_name = (
                    f"{port['service']['product']} - {port['service']['name']}"
                )
            except KeyError:
                service_name = f"{port['service']['name']}"
            vulnerabilities.append({"service": service_name, "vuln_list": vuln_list})
    return {"services": services, "vulnerabilities": vulnerabilities}


def tls_version_check(domain: str, service):
    """
    Checks the version of TLS.
    """
    try:
        domain_name(domain)
    except Exception:
        return {"status": False, "statusmessage": "The given domain is invalid!"}
    nmap = nmap3.Nmap()
    logger.info(f"tls scan: Scanning host/domain {domain}")
    tls_scans = nmap.nmap_version_detection(domain, args="--script ssl-enum-ciphers")
    ip, tls_scans = list(tls_scans.items())[0]
    tls_scans = list(
        filter(lambda element: element["state"] == "open", tls_scans["ports"])
    )

    results = None

    for port in tls_scans:
        logger.info(f"tls scan: Testing port {port.get('portid')}")
        if service == "web":
            if (
                (port.get("service").get("name") == "ssl")
                or (
                    port.get("portid") == "443"
                    and port.get("service").get("name") == "http"
                )
                or (port.get("service").get("name") == "https")
            ):
                for script in port["scripts"]:
                    if script.get("name") == "ssl-enum-ciphers":
                        results = script["data"]
        elif service == "mail":
            if port.get("portid") == "25":
                for script in port["scripts"]:
                    if script.get("name") == "ssl-enum-ciphers":
                        results = script["data"]

    try:
        results.pop("least strength", None)
    except AttributeError:
        pass
    for k in results.keys():
        results[k] = results[k]["ciphers"]["children"]

    lowest_sec_level = {}
    for tls_version in results:
        for ciphersuite in results[tls_version]:
            ciphersuite.pop("strength")
            try:
                cipher_info = json.loads(
                    requests.get(
                        f"https://ciphersuite.info/api/cs/{ciphersuite['name']}"
                    ).text
                )[ciphersuite["name"]]
            except Exception:
                continue
            for key in ["gnutls_name", "openssl_name", "hex_byte_1", "hex_byte_2"]:
                cipher_info.pop(key)
            cipher_info["tls_version"] = tls_version
            ciphersuite.update(cipher_info)
        ci = load_cipher_info(results[tls_version])
        results[tls_version] = ci["result"]
        lowest_sec_level.update({f"{tls_version}": ci["lowest_sec_level"]})
    logger.info("server scan: Done!")
    return {"result": results, "lowest_sec_level": lowest_sec_level}


def check_dkim_public_key(domain: str, selectors: list):
    """Looks for a DKIM public key in a DNS field and verifies that it can be used to
    encrypt data."""
    try:
        domain_name(domain)
    except Exception:
        return {"status": False, "statusmessage": "The given domain is invalid!"}
    if len(selectors) == 0:
        # TODO Check to get proper selector or have a database of selectors
        selectors = [
            "selector1",
            "selector2",
            "google",
            "dkim",
            "k1",
            "default",
            "mxvault",
            "mail",
        ]
    for selector in selectors:
        try:
            dns_response = (
                dns.resolver.query(f"{selector}._domainkey.{domain}.", "TXT")
                .response.answer[1]
                .to_text()
            )
            p = re.search(r"p=([\w\d/+]*)", dns_response).group(1)
            key = RSA.importKey(b64decode(p))
            return {"dkim": key.can_encrypt()}
        except Exception:
            continue
    return {"dkim": False}


def get_pdf_report():
    # Render the HTML file
    output_from_parsed_template = render_to_string(
        "report/template.html",
        {},
    )

    base_url = os.path.abspath("")
    htmldoc = HTML(string=output_from_parsed_template, base_url=base_url)

    stylesheets = [
        CSS(os.path.join(base_url, "css/custom.css")),
    ]

    return htmldoc.write_pdf(stylesheets=stylesheets)
