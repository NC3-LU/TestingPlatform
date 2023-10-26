from django import forms

from .models import FirmwareAnalysisRequest


class FirmwareAnalysisRequestForm(forms.ModelForm):
    class Meta:
        model = FirmwareAnalysisRequest
        fields = ["firmware_name", "firmware_vendor_name", "firmware_product_name", "firmware_file"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs["class"] = "form_control"
