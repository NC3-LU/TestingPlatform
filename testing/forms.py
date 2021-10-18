from .models import DMARCRecord
from django import forms


class DMARCRecordForm(forms.ModelForm):
    class Meta:
        model = DMARCRecord
        fields = ['domain', 'policy', 'spf_policy', 'dkim_policy']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs['class'] = 'form-control'
