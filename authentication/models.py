from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    company_name = models.CharField(max_length=200)
    address = models.CharField(max_length=200)
    post_code = models.CharField(max_length=200)
    city = models.CharField(max_length=200)
    vat_number = models.CharField(max_length=200)
    ldih_uuid = models.CharField(max_length=200, blank=True, null=True)
