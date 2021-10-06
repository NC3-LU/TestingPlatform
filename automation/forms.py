from django import forms
from .models import PingAutomatedTest


class PingAutomatedTestForm(forms.ModelForm):
    class Meta:
        model = PingAutomatedTest
        fields = ['host', 'frequency', 'time', 'weekday', 'monthly_test_date']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs['class'] = 'form-control'
