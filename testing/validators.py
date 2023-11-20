import re

from rest_framework.serializers import ValidationError

pattern = re.compile(
    r"^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|"
    r"([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|"
    r"([a-zA-Z0-9][-_.a-zA-Z0-9]{0,61}[a-zA-Z0-9]))\."
    r"([a-zA-Z]{2,13}|[a-zA-Z0-9-]{2,30}.[a-zA-Z]{2,3})$"
)


def domain_name(value):
    """
    Return whether or not given value is a valid domain.
    See:
    https://validators.readthedocs.io/en/latest/_modules/validators/domain.html#domain
    """
    res = pattern.match(value)
    if res:
        return True
    else:
        raise ValidationError("This field must be a domain name.")


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
