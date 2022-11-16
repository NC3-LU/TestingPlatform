from datetime import datetime

from django import template

register = template.Library()


@register.filter("timestamp_to_time")
def convert_timestamp_to_time(timestamp):
    return datetime.fromtimestamp(int(timestamp))
