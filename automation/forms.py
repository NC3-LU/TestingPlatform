from django import forms

from .models import HttpAutomatedTest
from .models import PingAutomatedTest
from .models import WhoisAutomatedTest
from testing.models import UserDomain


class AutomatedTestForm(forms.ModelForm):
    def __init__(self, user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["target"].queryset = UserDomain.objects.filter(user=user)
        for visible in self.visible_fields():
            visible.field.widget.attrs["class"] = "form-control"


class PingAutomatedTestForm(AutomatedTestForm):
    class Meta:
        model = PingAutomatedTest
        fields = ["target", "frequency", "time", "weekday", "monthly_test_date"]
        widgets = {"time": forms.TimeInput(attrs={"type": "time"})}


class WhoisAutomatedTestForm(AutomatedTestForm):
    class Meta:
        model = WhoisAutomatedTest
        fields = ["target", "frequency", "time", "weekday", "monthly_test_date"]
        widgets = {"time": forms.TimeInput(attrs={"type": "time"})}


class HttpAutomatedTestForm(AutomatedTestForm):
    class Meta:
        model = HttpAutomatedTest
        fields = ["target", "frequency", "time", "weekday", "monthly_test_date"]
        widgets = {"time": forms.TimeInput(attrs={"type": "time"})}
