from django import forms

from .models import DMARCRecord, MailDomain


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
