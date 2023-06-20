import datetime
import socket

from django.core.mail import send_mail


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
