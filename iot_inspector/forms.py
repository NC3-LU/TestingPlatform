from django import forms

from .models import AnalysisRequest


class AnalysisRequestForm(forms.ModelForm):
    class Meta:
        model = AnalysisRequest
        fields = ["name", "vendor_name", "product_name", "file"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs["class"] = "form-control"
