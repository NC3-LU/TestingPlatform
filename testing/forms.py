from urllib.parse import urlsplit

import idna
from django import forms
from django.core.exceptions import ValidationError
from django.core.validators import DomainNameValidator

from .models import DMARCRecord, MailDomain, TestReport


class WebTestForm(forms.Form):
    invalid_target = (
        "Enter a valid domain such as test-domain.lu or www.test-domain.lu, "
        "or an HTTP(S) website URL without credentials or a port number."
    )
    target = forms.CharField(
        max_length=2048,
        error_messages={"required": invalid_target, "max_length": invalid_target},
    )

    def clean_target(self):
        value = self.cleaned_data["target"]
        try:
            if "\\" in value or any(character.isspace() for character in value):
                raise ValueError("Invalid whitespace or backslash")
            parsed = urlsplit(value if "://" in value else f"https://{value}")
            if (
                parsed.scheme not in ("http", "https")
                or parsed.username is not None
                or parsed.password is not None
                or parsed.port is not None
                or not parsed.hostname
            ):
                raise ValueError("Expected a website hostname")
            DomainNameValidator()(parsed.hostname)
            domain = idna.encode(parsed.hostname.removesuffix("."), uts46=True).decode(
                "ascii"
            )
            if len(domain) > TestReport._meta.get_field("tested_site").max_length:
                raise ValueError("Domain is too long for a saved report")
            return domain
        except (ValidationError, ValueError, UnicodeError):
            raise forms.ValidationError(self.invalid_target) from None


class DMARCRecordForm(forms.ModelForm):
    class Meta:
        model = DMARCRecord
        fields = ["domain", "policy", "spf_policy", "dkim_policy", "mailto"]

    def __init__(self, user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs["class"] = "form-control"


class SPFRecordForm(forms.Form):
    policy = forms.ChoiceField(
        choices=(("-all", "Strict"), ("?all", "Neutral"), ("~all", "Soft fail")),
        help_text="Select policy for servers not listed in your SPF record",
    )
    hosts = forms.CharField(
        max_length=200,
        help_text="Please write all hosts that are allowed to send mails for your "
        'domain, comma separated (i.e. "1.1.1.1, mx.mydomain.com, '
        '2.2.2.2")',
        required=True,
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs["class"] = "form-control"
