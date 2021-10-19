from django import forms
from django.db.models import QuerySet

from .models import PingAutomatedTest, HttpAutomatedTest
from testing.models import UserDomain


class PingAutomatedTestForm(forms.ModelForm):
    class Meta:
        model = PingAutomatedTest
        fields = ['target', 'frequency', 'time', 'weekday', 'monthly_test_date']

    def __init__(self, targets, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['target'].queryset = targets
        for visible in self.visible_fields():
            visible.field.widget.attrs['class'] = 'form-control'


class HttpAutomatedTestForm(forms.ModelForm):
    class Meta:
        model = HttpAutomatedTest
        fields = ['target', 'frequency', 'time', 'weekday', 'monthly_test_date']

    def __init__(self, targets, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['target'].queryset = targets
        for visible in self.visible_fields():
            visible.field.widget.attrs['class'] = 'form-control'
