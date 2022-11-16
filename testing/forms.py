from .models import DMARCRecord
from .models import MailDomain
from django import forms


class DMARCRecordForm(forms.ModelForm):
    class Meta:
        model = DMARCRecord
        fields = ["domain", "policy", "spf_policy", "dkim_policy"]

    def __init__(self, user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["domain"].queryset = MailDomain.objects.filter(user=user)
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
        required=False,
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs["class"] = "form-control"
