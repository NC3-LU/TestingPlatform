from django.db import models
from django.contrib.auth.models import AbstractUser


class User(AbstractUser):
    vat_number = models.CharField(max_length=200, blank=True, null=True)
    company_name = models.CharField(max_length=200)

