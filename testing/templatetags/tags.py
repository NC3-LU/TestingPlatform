import ipaddress
import socket

from django import template
from django.utils.safestring import mark_safe
from ipwhois import exceptions
from ipwhois import IPWhois

register = template.Library()


@register.filter("get_host")
def get_host(address):
    if address is not None:
        try:
            # return socket.gethostbyaddr(address)[0]
            return None
        except socket.gaierror:
            return "Can't get host from IP"
    else:
        return "No IP to check"


@register.filter("get_ip")
def get_ip(domain):
    if domain is not None:
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            return "Can't fetch IP from host"
    else:
        return "No domain to check"


@register.filter("get_asn")
def get_asn(address):
    if ipaddress.ip_address(address):
        try:
            obj = IPWhois(address)
            d = obj.lookup_rdap(depth=1)
            result = f"""
                        ASN:{d["asn"]}<br>
                        ASN Description: {d["asn_description"]}<br>
                        ASN Registry: {d["asn_registry"]}<br>
                        Entities: {d["entities"]}
                     """
        except exceptions.HTTPLookupError:
            result = ""
    else:
        result = "No IP for ASN"
    return mark_safe(result)
