import datetime
import os
import socket
import subprocess
import sys
from typing import Any, Dict, List

from django.core.mail import send_mail

from authentication.models import User
from testing_platform.settings import BASE_DIR


def check_mail():
    """
    Checks if the SMTP connection is working.
    """
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


def get_version():
    """
    Returns the version of the software and the address of the exact commit
    on the project home page.
    Try to get the version from the Git tags.
    """
    version_res = (
        os.environ.get("PKGVER")
        or subprocess.run(
            ["git", "-C", BASE_DIR, "describe", "--tags"], stdout=subprocess.PIPE
        )
        .stdout.decode()
        .strip()
    )  # Type: str
    version = version_res.split("-")
    if len(version) == 1:
        app_version = version[0]
        version_url = (
            "https://github.com/NC3-LU/TestingPlatform/releases/tag/{}".format(
                version[0]
            )
        )
    else:
        app_version = f"{version[0]} - {version[2][1:]}"
        version_url = "https://github.com/NC3-LU/TestingPlatform/commits/{}".format(
            version[2][1:]
        )
    return {"app_version": app_version, "version_url": version_url}


def health():
    """
    Returns various informations on the health of the software.
    """
    result: Dict[str, Any] = {
        "python_version": "{}.{}.{}".format(*sys.version_info[:3]),
        "database": {},
    }
    result.update(get_version())
    result["database"]["SQL"] = True if User.objects.all().count() >= 1 else False
    # result["database"]["kvrocks"] = False
    result["email"] = check_mail()
    return result


def exec_cmd_no_wait(cmd: List) -> None:
    """Execute a command in a sub process to."""
    subprocess.Popen(cmd, stdout=subprocess.PIPE, cwd=BASE_DIR)
