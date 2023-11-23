import sys
from io import BytesIO

from api.validators import pattern
from testing_platform.settings import MAX_UPLOAD_FILE_SIZE


def file_size(file: BytesIO):
    """
    Validates the size of the file.
    """
    if sys.getsizeof(file) > MAX_UPLOAD_FILE_SIZE:
        raise Exception(
            f"The file size can not be more than {MAX_UPLOAD_FILE_SIZE} bytes."
        )
    return file


def full_domain_validator(value):
    res = pattern.match(value)
    if res:
        return value
    else:
        raise Exception("This field must be a domain name.")
