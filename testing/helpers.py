import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone, timedelta
from dateutil.relativedelta import relativedelta
from base64 import b64decode
from io import BytesIO
from typing import Any, Union, Dict
from bs4 import BeautifulSoup
import dns.resolver
import dns.dnssec
import dns.name
import ssl
import socket
import dns.message
import dns.rdatatype
import dns.resolver
import nmap3
import pypandora
import requests
import hashlib
import base64
import smtplib as smtp
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from Crypto.PublicKey import RSA
from django.template.loader import render_to_string
from weasyprint import CSS, HTML
from typing import Dict, List, Tuple
import logging
from testing import validators
from testing_platform.settings import PANDORA_ROOT_URL
from .cipher_scoring import load_cipher_info
from pyvulnerabilitylookup import PyVulnerabilityLookup
from pylookyloo import Lookyloo

logger = logging.getLogger(__name__)


def check_soa_record(target: str) -> Union[bool, Dict]:
    """Checks the presence of a SOA record for the Email Systems Testing."""
    try:
        validators.full_domain_validator(target)
    except Exception:
        return {"error": "You entered an invalid hostname!"}
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
        target = validators.full_domain_validator(target)
    except Exception:
        return {"error": "You entered an invalid hostname!"}
    result = {}
    env = os.environ.copy()
    cmd = [
        os.path.join(sys.exec_prefix, "bin/checkdmarc"),
        target,
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
    try:
        validators.file_size(file_in_memory)
    except Exception as e:
        raise e

    pandora_cli = pypandora.PyPandora(root_url=PANDORA_ROOT_URL)
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
    # Validate the domain
    if not validators.full_domain_validator(domain):
        return {"error": "You entered an invalid hostname!"}

    nmap = nmap3.Nmap()
    logger.info(f"server scan: testing {domain}")

    try:
        service_scans = nmap.nmap_version_detection(domain, args="--script vulners --script-args mincvss+5.0")
    except Exception as e:
        logger.error(f"Error during Nmap scan: {e}")
        return {"error": "Nmap scan failed"}

    services = []
    vulnerabilities = []

    try:
        ip, service_scans = list(service_scans.items())[0]
    except IndexError:
        return {"error": "No scan results found"}

    for port in service_scans.get("ports", []):
        if port["state"] != "closed":
            service = port.get("service", {})
            vulners = port.get("scripts", [])
            vuln_dict = {'cve': [], 'others': []}
            if vulners:
                vulners = vulners[0].get("data", {})
                for vuln, vulndata in vulners.items():
                    try:
                        items = vulndata.get("children", [])
                        for vulnerability in items:
                            vulnerability['severity'] = cvss_rating(vulnerability['cvss'])
                            if vulnerability["type"] == "cve":
                                vuln_info = lookup_cve(vulnerability['id'])
                                vulnerability["description"] = vuln_info['description']
                                vulnerability['cvss_details'] = vuln_info['cvss']
                                vulnerability['sightings'] = vuln_info['sightings']
                                vulnerability["link"] = f"https://vulnerability.circl.lu/vuln/{vulnerability['id']}"
                                vuln_dict['cve'].append(vulnerability)
                            else:
                                vulnerability["link"] = f"https://vulners.com/{vulnerability['type']}/{vulnerability['id']}"
                                vuln_dict['others'].append(vulnerability)
                    except TypeError:
                        continue
                    except AttributeError:
                        continue

            services.append(service)
            try:
                vulnerabilities.append({
                    "service": f'{service.get("product", "Unknown")} - {service.get("name", "Unknown")}',
                    "vuln_dict": vuln_dict,
                })
            except KeyError:
                continue

    logger.info("server scan: Done!")

    return {"services": services, "vulnerabilities": vulnerabilities}


def cvss_rating(cvss_score):
    if float(cvss_score) >= 9:
        return "CRITICAL"
    elif 9 > float(cvss_score) >= 7:
        return "HIGH"
    elif 7 > float(cvss_score) >= 4:
        return "MEDIUM"
    else:
        return "LOW"


def lookup_cve(vuln_id):
    vuln_lookup = PyVulnerabilityLookup('https://vulnerability.circl.lu')
    if vuln_lookup.is_up:
        try:
            cve = vuln_lookup.get_vulnerability(vuln_id)
        except requests.exceptions.ConnectionError:
            cve = {}
        try:
            sightings = vuln_lookup.get_sightings(vuln_id=vuln_id, date_from=(datetime.now() - relativedelta(months=1)).date())
        except requests.exceptions.ConnectionError:
            sightings = {}

        containers = cve.get('containers', {})
        cna = containers.get('cna', {})
        adp = containers.get('adp', [{}])
        cve_info = {}

        # Description
        descriptions = cna.get('descriptions', [])
        for description in descriptions:
            if description.get('lang') == 'en':
                cve_info['description'] = description.get('value', 'N/A')
                break
            else:
                cve_info['description'] = 'N/A'

        # Severity
        metrics = cna.get('metrics', [])
        if not metrics:
            for item in adp:
                if 'metrics' in item:
                    metrics = item['metrics']
                    break

        if metrics:
            for metric in metrics:
                if 'cvssV3_1' in metric or 'cvssV4_0' in metric:
                    cvss_data = metric.get('cvssV3_1', {}) or metric.get('cvssV4_0', {})
                    cve_info['cvss'] = cvss_data
                    break
        else:
            cve_info['cvss'] = {}

        if sightings:
            dates = [
                datetime.fromisoformat(
                    sighting['creation_timestamp']).date()
                for sighting in sightings['data']
            ]
            date_counts = dict(Counter(dates))
            sightings['dates'] = [str(date) for date in date_counts.keys()]
            sightings['counts'] = list(date_counts.values())

        cve_info['sightings'] = {
            'total': sightings.get('metadata', {}).get('count', 0),
            'dates': sightings.get('dates', []),
            'counts': sightings.get('counts', [])
        }

        return cve_info


def web_server_check_no_raw_socket(hostname):
    try:
        validators.full_domain_validator(hostname)
    except Exception:
        return {"error": "You entered an invalid hostname!"}
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
                                info["link"] = f"https://cvepremium.circl.lu/cve/{info['id']}"
                            else:
                                info["link"] = f"https://vulners.com/{info['type']}/{info['id']}"
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
        validators.full_domain_validator(domain)
    except Exception:
        return {"error": "You entered an invalid hostname!"}
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
        validators.full_domain_validator(domain)
    except Exception:
        return {"error": "You entered an invalid hostname!"}
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


def check_dnssec(domain):
    """
    Check if DNSSEC is enabled for the domain.

    Args:
        domain (str): The domain to check.

    Returns:
        dict: A dictionary containing DNSSEC status and details.
    """
    result = {"enabled": False, "keys": [], "error": None}
    try:
        dnskey = dns.resolver.resolve(domain, 'DNSKEY')
        result["enabled"] = True
        result["keys"] = [key.to_text() for key in dnskey]
    except dns.resolver.NXDOMAIN:
        result["error"] = "Domain does not exist"
    except dns.resolver.NoAnswer:
        result["error"] = "No DNSKEY records found"
    except dns.exception.DNSException as e:
        result["error"] = f"DNS error: {str(e)}"
    except Exception as e:
        result["error"] = f"Unexpected error: {str(e)}"

    logger.info(f"DNSSEC check for {domain}: {'Enabled' if result['enabled'] else 'Disabled'}")
    if result["error"]:
        logger.warning(f"DNSSEC check error for {domain}: {result['error']}")

    return result


def check_mx(domain):
    """
    Check MX records for the domain.

    Args:
        domain (str): The domain to check.

    Returns:
        dict: A dictionary containing MX records and details.
    """
    result = {"records": [], "error": None}
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        result["records"] = [{"preference": mx.preference, "exchange": str(mx.exchange)} for mx in mx_records]
    except dns.resolver.NXDOMAIN:
        result["error"] = "Domain does not exist"
    except dns.resolver.NoAnswer:
        result["error"] = "No MX records found"
    except dns.exception.DNSException as e:
        result["error"] = f"DNS error: {str(e)}"
    except Exception as e:
        result["error"] = f"Unexpected error: {str(e)}"

    logger.info(f"MX check for {domain}: {len(result['records'])} records found")
    if result["error"]:
        logger.warning(f"MX check error for {domain}: {result['error']}")

    return result


def check_spf(domain):
    """
    Check SPF record for the domain.

    Args:
        domain (str): The domain to check.

    Returns:
        dict: A dictionary containing SPF record details.
    """
    result = {"record": None, "valid": False, "error": None}
    try:
        txt_records = dns.resolver.resolve(domain, 'TXT')
        for record in txt_records:
            if 'v=spf1' in str(record):
                result["record"] = record.to_text()
                result["valid"] = True
                break
    except dns.resolver.NXDOMAIN:
        result["error"] = "Domain does not exist"
    except dns.resolver.NoAnswer:
        result["error"] = "No TXT records found"
    except dns.exception.DNSException as e:
        result["error"] = f"DNS error: {str(e)}"
    except Exception as e:
        result["error"] = f"Unexpected error: {str(e)}"

    logger.info(f"SPF check for {domain}: {'Valid' if result['valid'] else 'Not found or invalid'}")
    if result["error"]:
        logger.warning(f"SPF check error for {domain}: {result['error']}")

    return result


def check_dmarc(domain: str) -> dict[str, bool | None | str | Any]:
    """
    Check the DMARC record for a given domain.

    Args:
        domain (str): The domain to check for DMARC record.

    Returns:
        dict: A dictionary containing DMARC record details.
    """
    result = {"record": None, "valid": False, "error": None}
    dmarc_domain = f'_dmarc.{domain}'

    try:
        dmarc_records = dns.resolver.resolve(dmarc_domain, 'TXT')

        for record in dmarc_records:
            record_text = record.to_text().strip('"')
            if record_text.startswith('v=DMARC1'):
                result['record'] = record_text
                result['valid'] = True
                break

        if not result['valid']:
            result['error'] = "No valid DMARC record found"

    except dns.resolver.NXDOMAIN:
        result['error'] = "Domain does not exist"
    except dns.resolver.NoAnswer:
        result['error'] = "No TXT records found"
    except dns.exception.DNSException as e:
        result['error'] = f"DNS error: {str(e)}"
    except Exception as e:
        result['error'] = f"Unexpected error: {str(e)}"

    logger.info(f"DMARC check for {domain}: {'Valid' if result['valid'] else 'Not found or invalid'}")
    if result['error']:
        logger.warning(f"DMARC check error for {domain}: {result['error']}")

    return result


def check_tls(mx_servers: List[str]) -> Dict[str, Dict[str, str]]:
    """
    Check TLS support for a list of mail servers across common SMTP ports.

    This function tests each provided mail server for TLS support on ports 25, 587, and 465.
    It uses multi-threading to check multiple servers concurrently for improved performance.

    For ports 25 and 587, it attempts to use STARTTLS to upgrade the connection to TLS.
    For port 465, it attempts to establish a direct SSL/TLS connection.

    The function performs strict certificate verification and hostname checking to ensure
    the security of the connections.

    Args:
    mx_servers (List[str]): A list of mail server hostnames to check.

    Returns:
    Dict[str, Dict[str, str]]: A nested dictionary where the outer key is the server hostname,
                               and the inner dictionary contains port numbers as keys and
                               TLS support status or error messages as values.

    Example return value:
    {
        "mail.example.com": {
            "mail.example.com:25": "TLS supported (STARTTLS)",
            "mail.example.com:587": "TLS supported (STARTTLS)",
            "mail.example.com:465": "TLS supported"
        }
    }

    Note:
    - The function limits concurrent threads to a maximum of 10 to prevent resource exhaustion.
    - Exceptions during the checking process are logged for debugging purposes.
    - SSL certificate verification errors are caught and reported separately from other errors.
    """

    def check_server(server: str) -> Tuple[str, Dict[str, str]]:
        results = {}
        ports = [25, 587, 465]  # Common SMTP ports
        for port in ports:
            try:
                context = ssl.create_default_context()
                context.check_hostname = True
                context.verify_mode = ssl.CERT_REQUIRED

                with socket.create_connection((server, port), timeout=5) as sock:
                    if port in (25, 587):
                        # For these ports, try STARTTLS
                        with smtp.SMTP(host=server, port=port, timeout=5) as smtp_conn:
                            smtp_conn.ehlo()
                            if smtp_conn.has_extn('STARTTLS'):
                                smtp_conn.starttls(context=context)
                                smtp_conn.ehlo()
                                results[f"{server}:{port}"] = "TLS supported (STARTTLS)"
                            else:
                                results[f"{server}:{port}"] = "TLS not supported"
                    elif port == 465:
                        # For 465, it should be SSL/TLS from the start
                        with context.wrap_socket(sock, server_hostname=server) as ssock:
                            cert = ssock.getpeercert()
                            ssl.match_hostname(cert, server)
                            results[f"{server}:{port}"] = "TLS supported"
            except ssl.SSLCertVerificationError:
                results[f"{server}:{port}"] = "TLS supported, but certificate verification failed"
            except Exception as e:
                results[f"{server}:{port}"] = f"Error: {str(e)}"
                logging.exception(f"Error checking {server}:{port}")
        return server, results

    tls_results = {}
    with ThreadPoolExecutor(max_workers=min(len(mx_servers), 10)) as executor:
        future_to_server = {executor.submit(check_server, server): server for server in mx_servers}
        for future in as_completed(future_to_server):
            server, result = future.result()
            tls_results[server] = result
    return tls_results


def check_dkim(domain, selector):
    dkim_domain = f'{selector}._domainkey.{domain}'
    try:
        dkim_record = dns.resolver.resolve(dkim_domain, 'TXT')
        for record in dkim_record:
            return record.to_text(), True
        return None, False
    except Exception as e:
        print(f'Error checking DKIM for {dkim_domain}: {e}')
        return None, False


def check_csp(domain):
    """
    Perform a comprehensive check of the Content Security Policy (CSP) for a given domain.

    Args:
        domain (str): The domain to check.

    Returns:
        dict: A dictionary with detailed CSP analysis results.
    """
    try:
        response = requests.get(f"https://{domain}", timeout=10)
        response.raise_for_status()

        csp_header = response.headers.get('Content-Security-Policy')
        csp_report_only = response.headers.get('Content-Security-Policy-Report-Only')

        result = {
            'status': False,
            'csp_value': csp_header,
            'csp_report_only': csp_report_only,
            'issues': [],
            'recommendations': []
        }

        if not csp_header and not csp_report_only:
            result['issues'].append("No Content-Security-Policy header found.")
            result['recommendations'].append(
                "Implement a Content-Security-Policy header.")
            return result

        headers_to_check = [
            ('Content-Security-Policy', csp_header),
            ('Content-Security-Policy-Report-Only', csp_report_only)
        ]

        for header_name, header_value in headers_to_check:
            if header_value:
                analyze_csp(header_value, result, header_name)

        result['status'] = len(result['issues']) == 0
        return result

    except requests.RequestException as e:
        return {
            'status': False,
            'csp_value': None,
            'csp_report_only': None,
            'issues': [f"An error occurred while fetching the page: {e}"],
            'recommendations': ["Ensure the domain is accessible and try again."]
        }


def analyze_csp(csp, result, header_name):
    directives = parse_csp(csp)

    check_unsafe_directives(directives, result, header_name)
    check_missing_directives(directives, result, header_name)
    check_overly_permissive_directives(directives, result, header_name)
    check_csp_syntax(csp, result, header_name)
    check_report_uri(directives, result, header_name)


def parse_csp(csp):
    return dict(
        directive.split(None, 1) for directive in csp.split(';') if directive.strip())


def check_unsafe_directives(directives, result, header_name):
    unsafe_directives = ['unsafe-inline', 'unsafe-eval', 'unsafe-hashes']
    for directive, value in directives.items():
        for unsafe in unsafe_directives:
            if unsafe in value:
                result['issues'].append(
                    f"{header_name}: Unsafe directive '{unsafe}' found in '{directive}'.")
                result['recommendations'].append(
                    f"Remove '{unsafe}' from the '{directive}' directive if possible.")


def check_missing_directives(directives, result, header_name):
    important_directives = ['default-src', 'script-src', 'style-src', 'img-src',
                            'connect-src', 'frame-src']
    for directive in important_directives:
        if directive not in directives:
            result['issues'].append(
                f"{header_name}: Missing important directive '{directive}'.")
            result['recommendations'].append(
                f"Consider adding the '{directive}' directive.")


def check_overly_permissive_directives(directives, result, header_name):
    for directive, value in directives.items():
        if '*' in value:
            result['issues'].append(
                f"{header_name}: Overly permissive wildcard '*' found in '{directive}'.")
            result['recommendations'].append(
                f"Restrict the '{directive}' directive to specific sources instead of using '*'.")


def check_csp_syntax(csp, result, header_name):
    if not re.match(r'^[a-zA-Z0-9\-]+\s+[^;]+(?:;\s*[a-zA-Z0-9\-]+\s+[^;]+)*$', csp):
        result['issues'].append(f"{header_name}: CSP syntax appears to be invalid.")
        result['recommendations'].append("Review and correct the CSP syntax.")


def check_report_uri(directives, result, header_name):
    if 'report-uri' not in directives and 'report-to' not in directives:
        result['issues'].append(f"{header_name}: No reporting directive found.")
        result['recommendations'].append(
            "Consider adding a 'report-uri' or 'report-to' directive for CSP violation reporting.")


def check_cookies(domain: str) -> Dict[str, Any]:
    """
    Check the security attributes of cookies for a given domain.

    Args:
        domain (str): The domain to check.

    Returns:
        dict: A dictionary with the overall security status and detailed information for each cookie.
              - 'status' (bool): True if all cookies have 'Secure' and 'HttpOnly' attributes, False otherwise.
              - 'cookies' (List[Dict]): A list of dictionaries with details for each cookie.
                  - 'name' (str): The name of the cookie.
                  - 'secure' (bool): True if the cookie has the 'Secure' attribute, False otherwise.
                  - 'http_only' (bool): True if the cookie has the 'HttpOnly' attribute, False otherwise.
              - 'message' (str): Additional information or error message.
    """
    try:
        response = requests.get(f"https://{domain}", timeout=10)
        response.raise_for_status()

        cookies = response.cookies
        cookie_details = []
        all_secure = True

        for cookie in cookies:
            secure = cookie.secure
            http_only = cookie.has_nonstandard_attr('HttpOnly')
            all_secure = all_secure and secure and http_only
            cookie_details.append({
                'name': cookie.name,
                'secure': secure,
                'http_only': http_only
            })

        message = 'Cookie security attributes check completed.'
        if not cookie_details:
            message = 'No cookies found for this domain.'

        return {
            'status': all_secure,
            'cookies': cookie_details,
            'message': message
        }
    except RequestException as e:
        return {
            'status': False,
            'cookies': [],
            'message': f'An error occurred: {str(e)}'
        }


def check_cors(domain):
    """
    Check the CORS settings for a given domain.

    Args:
        domain (str): The domain to check.

    Returns:
        dict: A dictionary with the CORS status and the relevant headers.
              - 'status' (bool): True if CORS is configured, False otherwise.
              - 'cors_headers' (dict): A dictionary of CORS-related headers and their values.
              - 'message' (str): Additional information or error message.
    """
    try:
        response = requests.options(f"https://{domain}", timeout=10)
        cors_headers = {
            'Access-Control-Allow-Origin': response.headers.get('Access-Control-Allow-Origin'),
            'Access-Control-Allow-Methods': response.headers.get('Access-Control-Allow-Methods'),
            'Access-Control-Allow-Headers': response.headers.get('Access-Control-Allow-Headers'),
            'Access-Control-Allow-Credentials': response.headers.get('Access-Control-Allow-Credentials')
        }
        if any(cors_headers.values()):
            return {
                'status': True,
                'cors_headers': cors_headers,
                'message': 'CORS headers are present.'
            }
        else:
            return {
                'status': False,
                'cors_headers': cors_headers,
                'message': 'CORS headers are not present.'
            }
    except requests.RequestException as e:
        return {
            'status': False,
            'cors_headers': {},
            'message': f'An error occurred: {e}'
        }


def check_https_redirect(domain):
    """
    Check if a domain correctly redirects from HTTP to HTTPS.

    Args:
        domain (str): The domain to check.

    Returns:
        dict: A dictionary with the redirection status and the target URL.
              - 'status' (bool): True if the domain correctly redirects to HTTPS, False otherwise.
              - 'redirect_url' (str): The URL to which the domain redirects or None if not applicable.
              - 'message' (str): Additional information or error message.
    """
    try:
        http_response = requests.get(f"http://{domain}", allow_redirects=False, timeout=10)
        if http_response.is_redirect and http_response.headers.get('Location', '').startswith('https'):
            return {
                'status': True,
                'redirect_url': http_response.headers.get('Location'),
                'message': 'HTTP to HTTPS redirection is properly configured.'
            }
        else:
            return {
                'status': False,
                'redirect_url': http_response.headers.get('Location'),
                'message': 'HTTP to HTTPS redirection is not properly configured.'
            }
    except requests.RequestException as e:
        return {
            'status': False,
            'redirect_url': None,
            'message': f'An error occurred: {e}'
        }


def check_referrer_policy(domain):
    """
    Check the Referrer Policy header for a given domain.

    Args:
        domain (str): The domain to check.

    Returns:
        dict: A dictionary with the status and the value of the 'Referrer-Policy' header.
              - 'status' (bool): True if 'Referrer-Policy' is set, False otherwise.
              - 'header_value' (str): The value of the 'Referrer-Policy' header or None if not present.
              - 'message' (str): Additional information or error message.
    """
    try:
        response = requests.get(f"https://{domain}", timeout=10)
        response.raise_for_status()
        referrer_policy = response.headers.get('Referrer-Policy')

        if referrer_policy:
            return {
                'status': True,
                'header_value': referrer_policy,
                'message': 'Referrer-Policy header is present.'
            }
        else:
            return {
                'status': False,
                'header_value': None,
                'message': 'Referrer-Policy header is not present.'
            }
    except requests.RequestException as e:
        return {
            'status': False,
            'header_value': None,
            'message': f'An error occurred: {e}'
        }


def check_sri(domain):
    """
    Check the Subresource Integrity (SRI) of cross-origin scripts and stylesheets on a given domain.
    Args:
        domain (str): The domain to check.
    Returns:
        dict: A dictionary with the overall SRI status and detailed information for each resource.
              - 'status' (str): 'neutral', 'green', or 'red' based on the SRI check results.
              - 'resources': A list of dictionaries with details for each script and stylesheet.
                  - 'type' (str): Either 'script' or 'stylesheet'.
                  - 'src' (str): The full source URL of the resource.
                  - 'is_cross_origin' (bool): True if the resource is from a different origin, False otherwise.
                  - 'has_integrity' (bool): True if the resource has an 'integrity' attribute, False otherwise.
                  - 'integrity_value' (str): The value of the 'integrity' attribute or None if not present.
                  - 'integrity_valid' (bool): True if the integrity attribute matches the resource content, False otherwise.
              - 'message' (str): Additional information or error message.
    """
    try:
        url = f"https://{domain}"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        scripts = soup.find_all('script', src=True)
        stylesheets = soup.find_all('link', rel='stylesheet', href=True)
        resource_details = []
        all_cross_origin_have_valid_integrity = True
        cross_origin_resources_exist = False

        for resource in scripts + stylesheets:
            resource_type = 'script' if resource.name == 'script' else 'stylesheet'
            src = urljoin(url, resource['src'] if resource_type == 'script' else resource['href'])
            integrity = resource.get('integrity')
            is_cross_origin = is_cross_origin_url(url, src)
            has_integrity = bool(integrity)
            integrity_valid = None

            if is_cross_origin:
                cross_origin_resources_exist = True
                if not has_integrity:
                    all_cross_origin_have_valid_integrity = False
                else:
                    integrity_valid = validate_integrity(src, integrity)
                    if not integrity_valid:
                        all_cross_origin_have_valid_integrity = False

            resource_details.append({
                'type': resource_type,
                'src': src,
                'is_cross_origin': is_cross_origin,
                'has_integrity': has_integrity,
                'integrity_value': integrity,
                'integrity_valid': integrity_valid if is_cross_origin else None
            })

        if not cross_origin_resources_exist:
            status = 'neutral'
            message = 'No cross-origin resources found. Consider implementing SRI for all resources as a best practice.'
        elif all_cross_origin_have_valid_integrity:
            status = 'green'
            message = 'All cross-origin resources have valid integrity attributes.'
        else:
            status = 'red'
            message = 'Some cross-origin resources are missing valid integrity attributes.'

        return {
            'status': status,
            'resources': resource_details,
            'message': message
        }
    except requests.RequestException as e:
        return {'status': 'red', 'resources': [], 'message': f'An error occurred: {e}'}


def is_cross_origin_url(base_url, url):
    """
    Check if a URL is cross-origin relative to a base URL.

    Args:
        base_url (str): The base URL to compare against.
        url (str): The URL to check.

    Returns:
        bool: True if the URL is cross-origin, False otherwise.
    """
    base_parsed = urlparse(base_url)
    url_parsed = urlparse(url)
    return (base_parsed.scheme != url_parsed.scheme or
            base_parsed.netloc != url_parsed.netloc)


def validate_integrity(src, integrity):
    """
    Validate the integrity of a resource against its SRI hash.

    Args:
        src (str): The source URL of the resource.
        integrity (str): The integrity value to check against.

    Returns:
        bool: True if the integrity is valid, False otherwise.
    """
    try:
        response = requests.get(src, timeout=10)
        response.raise_for_status()
        content = response.content

        # Split multiple integrity values
        integrity_values = integrity.split()

        for integrity_value in integrity_values:
            try:
                algo, provided_hash = integrity_value.split('-', 1)
                if algo not in ('sha256', 'sha384', 'sha512'):
                    continue

                hash_func = getattr(hashlib, algo)
                calculated_hash = base64.b64encode(hash_func(content).digest()).decode(
                    'utf-8')

                if calculated_hash == provided_hash:
                    return True
            except ValueError as e:
                print(f"Error parsing integrity value '{integrity_value}': {e}")
                continue

        return False
    except requests.RequestException as e:
        print(f"Error fetching resource from {src}: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error during integrity validation: {e}")
        return False


def check_x_content_type_options(domain):
    """
    Check the 'X-Content-Type-Options' header for a given domain.

    Args:
        domain (str): The domain to check.

    Returns:
        dict: A dictionary with the status and the value of the 'X-Content-Type-Options' header.
              - 'status' (bool): True if 'X-Content-Type-Options' is set to 'nosniff', False otherwise.
              - 'header_value' (str): The value of the 'X-Content-Type-Options' header or None if not present.
              - 'message' (str): Additional information or error message.
    """
    try:
        response = requests.get(f"https://{domain}", timeout=10)
        header_value = response.headers.get('X-Content-Type-Options')
        if header_value == 'nosniff':
            return {'status': True, 'header_value': header_value, 'message': 'Header is correctly set to nosniff.'}
        else:
            return {'status': False, 'header_value': header_value, 'message': 'Header is not set to nosniff.'}
    except requests.RequestException as e:
        return {'status': False, 'header_value': None, 'message': f'An error occurred: {e}'}


def check_hsts(domain: str) -> Dict[str, Union[bool, str, Dict[str, Union[str, bool, int]]]]:
    """
    Checks if the HTTP Strict Transport Security (HSTS) header is implemented and returns detailed information.
    Args:
        domain (str): The domain to check.
    Returns:
        dict: A dictionary with the HSTS check results.
              - 'status' (bool): True if the HSTS header is present, False otherwise.
              - 'data' (str): The raw HSTS header or an error message.
              - 'parsed' (dict): The parsed components of the HSTS header if present.
              - 'http_status' (int): The HTTP status code of the response.
              - 'preload_ready' (bool): Whether the HSTS header includes the preload directive.
              - 'strength' (str): Evaluation of the HSTS implementation strength.
              - 'recommendations' (list): List of recommendations for improving HSTS implementation.
    """
    url = f'https://{domain}'
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        hsts_header = response.headers.get('strict-transport-security')
        parsed_hsts = parse_hsts_header(hsts_header) if hsts_header else {}

        preload_ready = parsed_hsts.get('preload', False)
        strength, recommendations = evaluate_hsts_strength(parsed_hsts)

        return {
            'status': bool(hsts_header),
            'data': hsts_header or 'HSTS header not found.',
            'parsed': parsed_hsts,
            'http_status': response.status_code,
            'preload_ready': preload_ready,
            'strength': strength,
            'recommendations': recommendations
        }
    except requests.RequestException as e:
        return {
            'status': False,
            'data': f'Failed to fetch the domain: {str(e)}',
            'parsed': {},
            'http_status': getattr(e.response, 'status_code', None),
            'preload_ready': False,
            'strength': 'N/A',
            'recommendations': ['Ensure the domain is accessible and supports HTTPS.']
        }


def evaluate_hsts_strength(parsed_hsts: Dict[str, Union[str, bool, int]]) -> tuple[str, List[str]]:
    """Evaluate the strength of the HSTS implementation and provide recommendations."""
    strength = 'Weak'
    recommendations = []

    if not parsed_hsts:
        return 'None', ['Implement HSTS header']

    max_age = parsed_hsts.get('max-age', 0)
    if max_age < 31536000:  # Less than 1 year
        recommendations.append('Increase max-age to at least 1 year (31536000 seconds)')

    if not parsed_hsts.get('includeSubDomains'):
        recommendations.append('Add includeSubDomains directive')

    if not parsed_hsts.get('preload'):
        recommendations.append('Add preload directive')
    else:
        recommendations.append('Consider submitting domain to HSTS preload list: https://hstspreload.org/')

    if max_age >= 31536000 and parsed_hsts.get('includeSubDomains') and parsed_hsts.get('preload'):
        strength = 'Strong'
    elif max_age >= 15768000:  # 6 months
        strength = 'Moderate'

    return strength, recommendations

def parse_hsts_header(header: str) -> Dict[str, Union[str, bool, int]]:
    """Parse the HSTS header into its components."""
    components = header.split(';')
    parsed = {}
    for component in components:
        component = component.strip().lower()
        if component.startswith('max-age='):
            parsed['max-age'] = int(component.split('=')[1])
        elif component == 'includesubdomains':
            parsed['includeSubDomains'] = True
        elif component == 'preload':
            parsed['preload'] = True
    return parsed


def check_security_txt(domain: str) -> dict:
    """
    Check if the domain has a security.txt file and return its content if found.

    Args:
        domain (str): The domain to check.

    Returns:
        dict: A dictionary with the status and content of the security.txt file.
              - 'status' (bool): True if the security.txt file is found and readable, False otherwise.
              - 'data' (str): The content of the security.txt file or an error message.
    """
    url = f'https://{domain}/.well-known/security.txt'
    try:
        # First, check if the file exists using HEAD request
        head_response = requests.head(url, timeout=10)
        if head_response.status_code == 200:
            # If it exists, attempt to get the content
            try:
                response = requests.get(url, timeout=10)
                response.raise_for_status()
                return {'status': True, 'data': response.text}
            except requests.RequestException as e:
                return {'status': True, 'data': f'security.txt file found but cannot be read: {str(e)}'}
        elif head_response.status_code in (403, 401):
            return {'status': False, 'data': 'Access to security.txt is forbidden or unauthorized.'}
        elif head_response.status_code == 404:
            return {'status': False, 'data': 'security.txt file not found.'}
        else:
            return {'status': False, 'data': f'Unexpected HTTP status: {head_response.status_code}'}
    except requests.RequestException as e:
        return {'status': False, 'data': f'security.txt check failed: {str(e)}'}


def get_capture_result(lookyloo, capture_uuid):
    capture_results = lookyloo.get_modules_responses(capture_uuid)
    url = lookyloo.get_info(capture_uuid)['url']
    if len(url) > 60:
        url = url[:30] + ' [...] ' + url[-30:] + ' (shortened url)'
    virustotal = any(value is not None for value in capture_results['vt'].values())
    phishtank = any(value is not None for value in
                    capture_results['phishtank']['urls'].values())
    urlhaus = any(
        value is not None for value in capture_results['urlhaus']['urls'].values())
    if capture_results['urlscan']['result']:
        urlscan = capture_results['urlscan']['result']['verdicts']['overall'][
            'malicious']
    else:
        urlscan = False
    overall = virustotal or phishtank or urlhaus or urlscan
    return {
        'url': url,
        'virustotal': virustotal,
        'phishtank': phishtank,
        'urlhaus': urlhaus,
        'urlscan': urlscan,
        'overall': overall
    }


def get_recent_captures(lookyloo):
    ts = datetime.now(timezone.utc) - timedelta(weeks=1)
    recent_captures = lookyloo.get_recent_captures(timestamp=ts)[:10]
    print(recent_captures)
    for i in range(len(recent_captures)):
        recent_captures[i] = get_capture_result(lookyloo, recent_captures[i])
    return recent_captures
