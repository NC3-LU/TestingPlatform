import datetime
import os

from django.db import models

from authentication.models import User


def get_upload_path(instance, filename):
    return f"user_{instance.user.id}/{filename}"


class FirmwareAnalysisRequest(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    request_nb = models.CharField(max_length=12)
    firmware_name = models.CharField(max_length=200, blank=False, null=False)
    firmware_vendor_name = models.CharField(max_length=200, blank=False, null=False)
    firmware_product_name = models.CharField(max_length=200, blank=False, null=False)
    firmware_file = models.FileField(upload_to=get_upload_path)
    firmware_uuid = models.UUIDField(default=None, blank=True, null=True)
    status = models.BooleanField(default=None, blank=True, null=True)
    report_uuid = models.UUIDField(default=None, blank=True, null=True)
    report_link = models.URLField(default=None, blank=True, null=True)

    @property
    def filename(self):
        return os.path.basename(self.firmware_file.name)

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
                    FirmwareAnalysisRequest.objects.order_by("id").last().request_nb
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

        super().save(*args, **kwargs)
