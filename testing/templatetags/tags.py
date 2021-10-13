import socket
import html

from django.utils.safestring import mark_safe
from ipwhois import IPWhois
from django import template

register = template.Library()


@register.filter('get_host')
def get_host(address):
    if address is not None:
        try:
            # return socket.gethostbyaddr(address)[0]
            return None
        except socket.gaierror:
            return "Can't get host from IP"
    else:
        return "No IP to check"


@register.filter('get_ip')
def get_ip(domain):
    if domain is not None:
        try:
            # return socket.gethostbyname(domain)
            return None
        except socket.gaierror:
            return "Can't fetch IP from host"
    else:
        return "No domain to check"


@register.filter('get_asn')
def get_asn(address):
    if address is not None:
        obj = IPWhois(address)
        d = obj.lookup_rdap(depth=1)
        result = f"""
                ASN:{d["asn"]}<br>
                ASN Description: {d["asn_description"]}<br>
                ASN Registry: {d["asn_registry"]}<br>
                Entities: {d["entities"]}
                """
    else:
        result = "No IP for ASN"
        return mark_safe(result)
