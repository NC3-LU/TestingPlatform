from django.db import models
from django.contrib.auth import get_user_model
from django.core.validators import URLValidator
from django.conf import settings
from authentication.models import User
import uuid
import hashlib

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
        return self.domain + "_" + str(self.scan_id)


class DMARCRecord(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    domain = models.CharField(
        max_length=255,
        help_text="Please enter the domain name the record should be generated for",
    )
    policy = models.CharField(
        max_length=15,
        choices=(
            ("none", "Do nothing, just inform me (Recommended)"),
            ("quarantine", "Quarantine the email"),
            ("reject", "Reject the email"),
        ),
        default="none",
        help_text="How should the mail be treated?",
    )
    spf_policy = models.CharField(
        "SPF Policy",
        max_length=15,
        choices=(("relaxed", "Relaxed (Default)"), ("aspf=s; ", "Strict")),
        default="",
    )
    dkim_policy = models.CharField(
        "DKIM Policy",
        max_length=15,
        choices=(("relaxed", "Relaxed (Default)"), ("adkim=s; ", "Strict")),
        default="",
    )
    txt_record = models.CharField(max_length=100)
    dmarc_record = models.CharField(max_length=100)
    mailto = models.EmailField()

    def save(self, *args, **kwargs):
        domain = self.domain.replace("www.", "")
        self.txt_record = f"_dmarc.{domain}"

        if self.spf_policy == "relaxed":
            spf = ""
        else:
            spf = self.spf_policy

        if self.dkim_policy == "relaxed":
            dkim = ""
        else:
            dkim = self.dkim_policy

        self.dmarc_record = (
            f"v=DMARC1; p={self.policy}; {spf}{dkim}rua=mailto:{self.mailto};"
        )

        super().save(*args, **kwargs)

    def __str__(self):
        return f'{self.user.company_name}-{self.domain.replace("www.", "")}'


class DMARCReport(models.Model):
    dmarc_record = models.ForeignKey(DMARCRecord, on_delete=models.CASCADE)
    timestamp = models.CharField(max_length=15)
    mail_from = models.EmailField()
    report = models.JSONField()

    def __str__(self):
        return f"{self.dmarc_record}-{self.mail_from}-{self.timestamp}"


class TestReport(models.Model):
    tested_site = models.CharField(max_length=200, blank=True, null=True)
    test_ran = models.CharField(max_length=200, blank=True, null=True)
    report = models.JSONField()

    def __str__(self):
        return f"{self.test_ran}_{self.tested_site.replace('.', '-')}"


class CSPEndpoint(models.Model):
    """Represents a CSP reporting endpoint configuration"""
    user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
    allowed_origin = models.URLField(
        help_text="The domain allowed to send reports to this endpoint.",
        validators=[URLValidator(schemes=['https'])]
    )
    endpoint_uuid = models.CharField(max_length=64, unique=True, editable=False, db_index=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=['user', 'allowed_origin']),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=['user', 'allowed_origin'],
                name='unique_user_origin'
            )
        ]

    def save(self, *args, **kwargs):
        if not self.endpoint_uuid:
            namespace = uuid.uuid5(uuid.NAMESPACE_DNS, f"{settings.SECRET_KEY[:16]}:{self.user.id}")
            domain_uuid = uuid.uuid5(namespace, self.allowed_origin)
            self.endpoint_uuid = hashlib.blake2b(
                str(domain_uuid).encode(),
                salt=settings.SECRET_KEY[:16].encode(),
                digest_size=32
            ).hexdigest()
        super().save(*args, **kwargs)

class CSPReport(models.Model):
    """Stores CSP violation reports"""
    endpoint = models.ForeignKey(CSPEndpoint, on_delete=models.CASCADE)
    report_data = models.JSONField()  # Store the complete report
    user_agent = models.CharField(max_length=255, null=True)  # Useful for debugging browser-specific issues
    occurred_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        indexes = [
            models.Index(fields=['endpoint', 'occurred_at']),
        ]
