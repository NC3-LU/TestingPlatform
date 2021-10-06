from django.db import models
from django_q.models import Schedule
from django_q.tasks import schedule
import django.utils.timezone

from authentication.models import User
from automation.tasks import *

from datetime import datetime


# Create your models here.
class AutomatedTest(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    frequency = models.CharField(max_length=20, choices=(('D', 'Dayly'), ('W', 'Weekly'), ('M', 'Monthly')),
                                 help_text='Choose frequency of tests')
    time = models.TimeField(help_text='Choose time for test execution', default=django.utils.timezone.now)
    weekday = models.CharField(max_length=15, choices=(('mo', 'Monday'), ('tu', 'Tuesday'), ('we', 'Wednesday'),
                                                       ('th', 'Thursday'), ('fr', 'Friday'), ('sa', 'Saturday'),
                                                       ('su', 'Sunday')), help_text='If weekly, choose day of test',
                               blank=True, null=True)
    monthly_test_date = models.IntegerField(choices=tuple([(d, d) for d in range(1, 29)]),
                                            help_text='If monthly, select day in month up to the 28th',
                                            blank=True, null=True)
    schedule = models.OneToOneField(Schedule, on_delete=models.CASCADE)

    class Meta:
        abstract = True


class PingAutomatedTest(AutomatedTest):
    host = models.CharField(max_length=100, help_text='Host to be tested')

    def save(self, *args, **kwargs):
        days = {
            'mo': 1,
            'tu': 2,
            'we': 3,
            'th': 4,
            'fr': 5,
            'sa': 6,
            'su': 7,
        }
        minutes = self.time.minute
        hour = self.time.hour
        cron = ''
        if self.frequency == 'D':
            cron = f'{minutes} {hour} * * *'
        if self.frequency == 'W':
            cron = f'{minutes} {hour} * * {days[self.weekday]}'
        if self.frequency == 'M':
            cron = f'{minutes} {hour} {self.monthly_test_date} * *'

        self.schedule = Schedule(
            name=f'PingTest_{self.user.username}_{self.host}',
            func='automation.tasks.ping',
            args="'" + str(self.host) + "'",
            schedule_type=Schedule.CRON,
            cron=cron
        )

        self.schedule.save()
        super().save()

    def __str__(self):
        return self.schedule.name
