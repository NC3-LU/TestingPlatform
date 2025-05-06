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
    """
    Validates that a string is a valid domain name.
    
    Args:
        value (str): The domain name to validate
        
    Returns:
        str: The validated domain name
        
    Raises:
        Exception: If the domain name is invalid
    """
    if not value:
        raise Exception("Domain name cannot be empty.")
        
    if not isinstance(value, str):
        raise Exception("Domain name must be a string.")
    
    # Remove any leading/trailing whitespace
    value = value.strip()
    
    # Check for common invalid characters
    invalid_chars = ['<', '>', '"', "'", '\\', ' ']
    for char in invalid_chars:
        if char in value:
            raise Exception(f"Domain name contains invalid character: '{char}'")
    
    res = pattern.match(value)
    if res:
        return value
    else:
        raise Exception("Invalid domain name format. Please enter a valid domain (e.g., example.com).")
