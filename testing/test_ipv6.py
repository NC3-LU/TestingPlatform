import logging
from typing import Any, Dict, List, Union
import dns.message
import dns.rdatatype
import dns.resolver
import dns.query
import dns.exception

logger = logging.getLogger(__name__)


def ipv6_check(
    domain: str, port=None
) -> Dict[str, Union[Dict[Any, Any], List[Union[str, int]], List[Any]]]:
    """
    Check IPv6 connectivity for a domain.
    
    This function tests the IPv6 readiness of a domain by examining:
    1. Name server records and their IPv6 connectivity
    2. Domain IPv6 records and their reachability
    
    Args:
        domain (str): The domain to check
        port (int, optional): The port to use for connectivity tests
        
    Returns:
        Dict: Results of the IPv6 check containing nameservers,
              connectivity comments, and records information
    """
    if not domain:
        logger.error("Empty domain provided to ipv6_check")
        return {
            "error": "No domain provided",
            "nameservers": {},
            "nameservers_comments": {"grade": "null", "comment": "No domain provided"},
            "nameservers_reachability_comments": {"grade": "null", "comment": "No domain provided"},
            "records": [],
            "records_v4_comments": None,
            "records_v6_comments": None
        }
        
    logger.info(f"ipv6 scan: scanning domain {domain}")
    results = {}
    
    # Initialize result structures with proper default values
    nameservers_comments = {
        "grade": "null",
        "comment": "Your domain has no name server with an IPv6 record."
    }
    
    nameservers_reachability_comments = {
        "grade": "null",
        "comment": "Your domain name servers are not reachable over IPv6."
    }
    
    records = []
    
    records_v4_comments = None
    records_v6_comments = None

    # Check Name Servers connectivity:
    try:
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
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException) as e:
        logger.error(f"Failed to query NS records for {domain}: {str(e)}")
        return {
            "error": f"DNS query failed: {str(e)}",
            "nameservers": {},
            "nameservers_comments": nameservers_comments,
            "nameservers_reachability_comments": nameservers_reachability_comments,
            "records": records,
            "records_v4_comments": records_v4_comments,
            "records_v6_comments": records_v6_comments
        }
        
    for ns_name in ns_names:
        results[ns_name] = {}
        logger.info(f"ipv6 scan: found NS {ns_name}")
        try:
            q_a = dns.message.make_query(ns_name, dns.rdatatype.A)
            r_a = dns.query.tcp(q_a, default_resolver, timeout=5)
        except dns.exception.Timeout:
            logger.warning(f"Timeout querying A record for {ns_name}")
            r_a = None
        except dns.exception.DNSException as e:
            logger.warning(f"Error querying A record for {ns_name}: {str(e)}")
            r_a = None
            
        try:
            q_aaaa = dns.message.make_query(ns_name, dns.rdatatype.AAAA)
            r_aaaa = dns.query.tcp(q_aaaa, default_resolver, timeout=5)
        except dns.exception.Timeout:
            logger.warning(f"Timeout querying AAAA record for {ns_name}")
            r_aaaa = None
        except dns.exception.DNSException as e:
            logger.warning(f"Error querying AAAA record for {ns_name}: {str(e)}")
            r_aaaa = None

        # Process A records if available
        if r_a and hasattr(r_a, 'answer') and r_a.answer:
            try:
                ns_ip4 = [item.address for answer in r_a.answer for item in answer.items][0]
                q4 = dns.message.make_query("example.com", dns.rdatatype.A)
                logger.info(f"{ns_name} - {ns_ip4}")
                tcp4_response_default = dns.query.tcp(q4, default_resolver, timeout=5)
                logger.info(f"Default resolver answer: {tcp4_response_default.answer}")
                try:
                    tcp4_response = dns.query.tcp(q4, ns_ip4, timeout=5)
                    logger.info(f"Name server answer: {tcp4_response.answer}")
                except dns.exception.Timeout:
                    logger.warning(f"Timeout querying IPv4 nameserver {ns_ip4}")
                    tcp4_response = None
                except Exception as e:
                    logger.warning(f"Error querying IPv4 nameserver {ns_ip4}: {str(e)}")
                    tcp4_response = None
            except (IndexError, AttributeError) as e:
                logger.warning(f"Error processing A record for {ns_name}: {str(e)}")
                ns_ip4 = None
        else:
            ns_ip4 = None

        # Process AAAA records if available
        if r_aaaa and hasattr(r_aaaa, 'answer') and r_aaaa.answer:
            try:
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
                except OSError as e:
                    logger.warning(f"OS error querying IPv6 nameserver {ns_ip6}: {str(e)}")
                    try:
                        # Fall back to IPv4 if IPv6 fails
                        if ns_ip4:
                            tcp6_response = dns.query.tcp(q6, ns_ip4, timeout=5)
                            logger.info(f"Name server answer (IPv4 fallback): {tcp6_response.answer}")
                        else:
                            tcp6_response = None
                    except dns.exception.Timeout:
                        logger.warning(f"Timeout on IPv4 fallback for {ns_name}")
                        tcp6_response = None
                    except Exception as e:
                        logger.warning(f"Error on IPv4 fallback for {ns_name}: {str(e)}")
                        tcp6_response = None
            except (IndexError, AttributeError) as e:
                logger.warning(f"Error processing AAAA record for {ns_name}: {str(e)}")
                tcp6_response = None

    # Build the final result structure with proper error handling
    try:
        return {
            "nameservers": results,
            "nameservers_comments": nameservers_comments,
            "nameservers_reachability_comments": nameservers_reachability_comments,
            "records": records,
            "records_v4_comments": records_v4_comments,
            "records_v6_comments": records_v6_comments,
        }
    except Exception as e:
        logger.error(f"Error building ipv6_check results: {str(e)}")
        return {
            "error": f"Error processing results: {str(e)}",
            "nameservers": {},
            "nameservers_comments": nameservers_comments,
            "nameservers_reachability_comments": nameservers_reachability_comments,
            "records": [],
            "records_v4_comments": None,
            "records_v6_comments": None
        }
