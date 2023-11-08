import datetime
import socket
import sys
from typing import Any, Dict

from django.core.mail import send_mail

from authentication.models import User
from testing_platform.context_processors import get_version


def check_mail():
    try:
        send_mail(
            subject=f"Test email from {socket.gethostname()} on {datetime.datetime.now()}",
            message="If you're reading this, it was successful.",
            from_email=None,
            recipient_list="root@localhost",
        )
        return True
    except Exception:
        return False


def health():
    result: Dict[str, Any] = {
        "python_version": "{}.{}.{}".format(*sys.version_info[:3]),
        "database": {},
    }
    result.update(get_version(None))
    result["database"]["SQL"] = True if User.objects.all().count() >= 1 else False
    # result["database"]["kvrocks"] = False
    result["email"] = check_mail()
    return result
