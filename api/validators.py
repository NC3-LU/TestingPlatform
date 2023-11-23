import re

from rest_framework.serializers import ValidationError

pattern = re.compile(
    r"^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|"
    r"([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|"
    r"([a-zA-Z0-9][-_.a-zA-Z0-9]{0,61}[a-zA-Z0-9]))\."
    r"([a-zA-Z]{2,13}|[a-zA-Z0-9-]{2,30}.[a-zA-Z]{2,3})$"
)


def service(value):
    if value not in ["web", "email"]:
        raise ValidationError("Service must be 'web' or 'email'.")
    return value


def file_size(file):
    if file.size > 5000000:
        raise ValidationError("The file size can not be more than 5000000 bytes.")
    return file


def domain_name(value):
    """
    Return whether or not given value is a valid domain.
    See:
    https://validators.readthedocs.io/en/latest/_modules/validators/domain.html#domain
    """
    res = pattern.match(value)
    if res:
        return value
    else:
        raise ValidationError("This field must be a domain name.")
