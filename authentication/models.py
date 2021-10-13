from django.db import models
from django.contrib.auth.models import AbstractUser


class User(AbstractUser):
    company_name = models.CharField(max_length=200)
    address = models.CharField(max_length=200)
    post_code = models.CharField(max_length=200)
    city = models.CharField(max_length=200)
    vat_number = models.CharField(max_length=200, blank=True, null=True)
    is_pro = models.BooleanField('PRO subscription', default=False)
    is_business = models.BooleanField('BUSINESS subscription', default=False)


class SubscriptionRequest(models.Model):
    user = models.ForeignKey(User, models.CASCADE)
    tier_level = models.CharField(max_length=15, choices=(('pro', 'PRO'), ('business', 'BUSINESS')))
    status = models.BooleanField(default=None, blank=True, null=True)

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
        return f'{self.user.username}_{self.tier_level}'
