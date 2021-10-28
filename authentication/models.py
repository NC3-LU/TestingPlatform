import django.utils.timezone
from django.db import models
from django.contrib.auth.models import AbstractUser
from datetime import datetime


class User(AbstractUser):
    company_name = models.CharField(max_length=200)
    address = models.CharField(max_length=200)
    post_code = models.CharField(max_length=200)
    city = models.CharField(max_length=200)
    vat_number = models.CharField(max_length=200, blank=True, null=True)
    tier_level = models.PositiveSmallIntegerField(choices=((0, 'None'), (1, 'PRO'), (2, 'BUSINESS')), default=0)


class SubscriptionBase(models.Model):
    tier_level = models.PositiveSmallIntegerField(choices=((1, 'PRO'), (2, 'BUSINESS')),
                                                  help_text='Choose a package')

    def get_tier_level(self):
        if self.tier_level == 1:
            tier = 'PRO'
        else:
            tier = 'BUSINESS'
        return tier

    def __str__(self):
        return f'{self.user.username}_{self.user.company_name}'

    class Meta:
        abstract = True


class Subscription(SubscriptionBase):
    user = models.OneToOneField(User, models.CASCADE)
    date_activated = models.DateField(default=django.utils.timezone.now)


class SubscriptionRequest(SubscriptionBase):
    user = models.ForeignKey(User, models.CASCADE)
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
        if self.tier_level == 1:
            tier = 'pro'
        else:
            tier = 'business'
        return f'{self.user.username}_{tier}'
