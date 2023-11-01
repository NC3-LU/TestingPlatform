import logging
from typing import Any, Dict, List, Union

import dns.message
import dns.rdatatype
import dns.resolver

logger = logging.getLogger(__name__)


def ipv6_check(
    domain: str, port=None
) -> Dict[str, Union[Dict[Any, Any], List[Union[str, int]], List[Any]]]:
    logger.info(f"ipv6 scan: scanning domain {domain}")
    results = {}

    # Check Name Servers connectivity:
    default_resolver = dns.resolver.Resolver().nameservers[0]
    logger.info(f"ipv6 scan: default resolver is {default_resolver}")
    q = dns.message.make_query(domain, dns.rdatatype.NS)
    ns_response = dns.query.tcp(q, default_resolver)
    ns_names = [
        t.target.to_text()
        for ans in ns_response.answer
        for t in ans
        if hasattr(t, "target")
    ]
    logger.info(f"ipv6 scan: {len(ns_names)} name servers in domain {domain}")
    for ns_name in ns_names:
        results[ns_name] = {}
        logger.info(f"ipv6 scan: found NS {ns_name}")
        try:
            q_a = dns.message.make_query(ns_name, dns.rdatatype.A)
            r_a = dns.query.tcp(q_a, default_resolver, timeout=5)
        except dns.exception.Timeout:
            r_a = None
        try:
            q_aaaa = dns.message.make_query(ns_name, dns.rdatatype.AAAA)
            r_aaaa = dns.query.tcp(q_aaaa, default_resolver, timeout=5)
        except dns.exception.Timeout:
            r_aaaa = None

        if r_a.answer:
            ns_ip4 = [item.address for answer in r_a.answer for item in answer.items][0]
            q4 = dns.message.make_query("example.com", dns.rdatatype.A)
            logger.info(f"{ns_name} - {ns_ip4}")
            tcp4_response_default = dns.query.tcp(q4, default_resolver, timeout=5)
            logger.info(f"Default resolver answer: {tcp4_response_default.answer}")
            try:
                tcp4_response = dns.query.tcp(q4, ns_ip4, timeout=5)
                logger.info(f"Name server answer: {tcp4_response.answer}")
            except dns.exception.Timeout:
                tcp4_response = None
        else:
            ns_ip4 = None

        if r_aaaa.answer:
            ns_ip6 = [
                item.address for answer in r_aaaa.answer for item in answer.items
            ][0]
            q6 = dns.message.make_query("example.com", dns.rdatatype.AAAA)
            logger.info(f"{ns_name} - {ns_ip6}")
            tcp6_response_default = dns.query.tcp(q6, default_resolver, timeout=5)
            logger.info(f"Default resolver answer: {tcp6_response_default.answer}")
            try:
                tcp6_response = dns.query.tcp(q6, ns_ip6, timeout=5)
                logger.info(f"Name server answer: {tcp6_response.answer}")
            except OSError:
                try:
                    tcp6_response = dns.query.tcp(q6, ns_ip4, timeout=5)
                    logger.info(f"Name server answer: {tcp6_response.answer}")
                except dns.exception.Timeout:
                    tcp6_response = None

    return {
        "nameservers": results,
        "nameservers_comments": nameservers_comments,
        "nameservers_reachability_comments": nameservers_reachability_comments,
        "records": records,
        "records_v4_comments": records_v4_comments,
        "records_v6_comments": records_v6_comments,
    }
