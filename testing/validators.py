from api.validators import pattern


def full_domain_validator(value):
    res = pattern.match(value)
    if res:
        return value
    else:
        raise Exception("This field must be a domain name.")
