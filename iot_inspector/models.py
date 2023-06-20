import datetime
import os
import secrets

from django.core.signing import Signer
from django.db import models

from authentication.models import User


def get_upload_path(instance, filename):
    return f"user_{instance.user.id}/{filename}"


class IOTUser(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    login = models.EmailField()
    password = models.CharField(max_length=200, editable=False)
    activated = models.BooleanField(default=False)

    def status_prop(self):
        if self.activated is False:
            alert = "Not onboarded"
        else:
            alert = "Activated"
        return alert

    status_field = property(status_prop)

    def save(self, *args, **kwargs):
        password = secrets.token_urlsafe(32)
        signer = Signer()
        self.password = signer.sign_object(password)
        self.email = self.user.email
        super().save(*args, **kwargs)

    def __str__(self):
        return self.user.username


class AnalysisRequest(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    iot_user = models.ForeignKey(IOTUser, on_delete=models.CASCADE, default=None)
    request_nb = models.CharField(max_length=12)
    name = models.CharField(max_length=200)
    vendor_name = models.CharField(max_length=200)
    product_name = models.CharField(max_length=200)
    file = models.FileField(upload_to=get_upload_path)
    status = models.BooleanField(default=None, blank=True, null=True)
    firmware_uuid = models.UUIDField(default=None, blank=True, null=True)
    report_uuid = models.UUIDField(default=None, blank=True, null=True)
    report_link = models.URLField(default=None, blank=True, null=True)

    @property
    def filename(self):
        return os.path.basename(self.file.name)

    def status_prop(self):
        if self.status is False:
            alert = "Declined"
        elif self.status is None:
            alert = "Pending"
        else:
            alert = "Validated"
        return alert

    status_field = property(status_prop)

    def __str__(self):
        return f"Request {self.request_nb}"

    def save(self, *args, **kwargs):
        request_date = datetime.date.today()
        if not self.request_nb:
            try:
                request_id = int(
                    AnalysisRequest.objects.order_by("id").last().request_nb
                )
                if request_id:
                    self.request_nb = request_id + 1
                else:
                    pass
            except Exception:
                request_id = 1
                self.request_nb = (
                    f'{request_date.year}{request_date.month}{(2-len(str(request_date.day)))*"0"}'
                    f'{request_date.day}{(3-len(str(request_id)))*"0"}{request_id}'
                )

        self.iot_user = self.user.iotuser

        super().save(*args, **kwargs)
