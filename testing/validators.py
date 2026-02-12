from typing import Union

from django.core.exceptions import ValidationError

from api.validators import pattern
from testing_platform.settings import MAX_UPLOAD_FILE_SIZE


def file_size(file: Union[bytes, bytearray]):
    """
    Validates the size of the file content.
    """
    if len(file) > MAX_UPLOAD_FILE_SIZE:
        raise ValidationError(
            f"The file size can not be more than {MAX_UPLOAD_FILE_SIZE} bytes."
        )
    return file


def full_domain_validator(value):
    """
    Validates that a string is a valid domain name.

    Args:
        value (str): The domain name to validate

    Returns:
        str: The validated domain name

    Raises:
        ValidationError: If the domain name is invalid
    """
    if not value:
        raise ValidationError("Domain name cannot be empty.")

    if not isinstance(value, str):
        raise ValidationError("Domain name must be a string.")

    # Remove any leading/trailing whitespace
    value = value.strip()

    # Check for common invalid characters
    invalid_chars = ["<", ">", '"', "'", "\\", " "]
    for char in invalid_chars:
        if char in value:
            raise ValidationError(
                f"Domain name contains invalid character: '{char}'"
            )

    res = pattern.match(value)
    if res:
        return value
    else:
        raise ValidationError(
            "Invalid domain name format. Please enter a valid domain (e.g., example.com)."
        )
