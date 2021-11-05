import socket
import urllib
from django.db import models
from authentication.models import User


class Domain(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    domain = models.CharField(max_length=255)

    class Meta:
        abstract = True

    def __str__(self):
        return self.domain


class UserDomain(Domain):
    ip_address = models.GenericIPAddressField(blank=True, null=True)


class MailDomain(Domain):
    pass


class TlsScanHistory(models.Model):
    scan_id = models.IntegerField()
    domain = models.CharField(max_length=255, unique=True)

    def __str__(self):
        return self.domain + '_' + str(self.scan_id)


class DMARCRecord(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    domain = models.OneToOneField(MailDomain, on_delete=models.CASCADE,
                                  help_text='Please select the domain name the record should be generated for')
    policy = models.CharField(max_length=15, choices=(('none', 'Do nothing, just inform me (Recommended)'),
                                                      ('quarantine', 'Quarantine the email'),
                                                      ('reject', 'Reject the email')), default='none',
                              help_text='How should the mail be treated?')
    spf_policy = models.CharField('SPF Policy', max_length=15, choices=(('relaxed', 'Relaxed (Default)'),
                                                                        ('aspf=s; ', 'Strict')), default='')
    dkim_policy = models.CharField('DKIM Policy', max_length=15, choices=(('relaxed', 'Relaxed (Default)'),
                                                                          ('adkim=s; ', 'Strict')), default='')
    txt_record = models.CharField(max_length=100)
    dmarc_record = models.CharField(max_length=100)
    mailto = models.EmailField()

    def save(self, *args, **kwargs):
        domain = self.domain.domain.strip('www.')
        orga = self.user.company_name.replace(" ", "_")
        self.mailto = f'report+{urllib.parse.quote_plus(orga)}-{domain}@test-dmarc.lu'

        self.txt_record = f'_dmarc.{domain}'

        if self.spf_policy == 'relaxed':
            spf = ''
        else:
            spf = self.spf_policy

        if self.dkim_policy == 'relaxed':
            dkim = ''
        else:
            dkim = self.dkim_policy

        self.dmarc_record = f'v=DMARC1; p={self.policy}; {spf}{dkim}rua=mailto:{self.mailto};'

        super().save()

    def __str__(self):
        return f'{self.user.company_name}-{self.domain.domain.strip("www.")}'


class DMARCReport(models.Model):
    dmarc_record = models.ForeignKey(DMARCRecord, on_delete=models.CASCADE)
    timestamp = models.CharField(max_length=15)
    mail_from = models.EmailField()
    report = models.JSONField()

    def __str__(self):
        return f'{self.dmarc_record}-{self.mail_from}-{self.timestamp}'
