from django.db import models

# Create your models here.
from authentication.models import User


class PingTestOld(models.Model):
    ip_ping_target = models.CharField(max_length=45)
    hostname_ping_target = models.CharField(max_length=255)
    date = models.DateField()
    uid = models.UUIDField()


class PingTest(models.Model):
    ip_ping_target = models.CharField(max_length=45)


# class TlsCheck(models.Model):


class UserDomain(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    ip_address = models.GenericIPAddressField()
    domain = models.CharField(max_length=255)
