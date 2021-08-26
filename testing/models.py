from django.db import models

# Create your models here.

class PingTest_old(models.Model):
    ip_ping_target = models.CharField(max_length=45)
    hostname_ping_target = models.CharField(max_length=255)
    date = models.DateField()
    uid = models.UUIDField()

class PingTest(models.Model):
    ip_ping_target = models.CharField(max_length=45)